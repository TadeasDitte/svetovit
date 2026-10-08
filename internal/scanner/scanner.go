package scanner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/TadeasDitte/Svetovit/internal/detector"
	"github.com/TadeasDitte/Svetovit/internal/lockfile"
)

type Component struct {
	Vendor    string
	Product   string
	Version   string
	Ecosystem string
	LocalID   string

	Platform string
}

var skipDirs = map[string]bool{
	"vendor":       true,
	"node_modules": true,
	".git":         true,
}

const UnlimitedDepth = -1

const DefaultWorkers = 4

// Mode sets how much of an install is searched once it is found.
type Mode int

const (
	// ModeSmall stops at an install root and reads only its plugins and their lock files.
	ModeSmall Mode = iota
	// ModeHalf also walks inside installs, finding nested installs and lock files, but skips the directories each
	// detector lists under skip: (uploads, caches, storage).
	ModeHalf
	// ModeFull walks everything below the target except vendor/, node_modules/ and .git/.
	ModeFull
)

func ParseMode(s string) (Mode, error) {
	switch s {
	case "small":
		return ModeSmall, nil
	case "half":
		return ModeHalf, nil
	case "full":
		return ModeFull, nil
	}
	return 0, fmt.Errorf("mode must be small, half or full, got %q", s)
}

type Scanner struct {
	registry         *detector.Registry
	maxDepth         int
	Workers          int
	Mode             Mode
	CrossFilesystems bool
	// OpsPerSecond caps filesystem operations across all workers; 0 means no cap.
	OpsPerSecond int
}

func New(registry *detector.Registry, maxDepth int) *Scanner {
	return &Scanner{registry: registry, maxDepth: maxDepth}
}

func (s *Scanner) workers() int {
	if s.Workers > 0 {
		return s.Workers
	}
	return DefaultWorkers
}

// site is a detected install. In small mode the walk stops at its root and everything below it is read by the
// detectors' plugin scan.
type site struct {
	root      string
	entries   []fs.DirEntry
	detectors []*detector.Detector
	parent    *site // the install this one is nested in, if any
}

// skips reports whether dir is a skip: directory of this install or of any install it is nested in.
func (st *site) skips(dir string) bool {
	for ; st != nil; st = st.parent {
		rel, err := filepath.Rel(st.root, dir)
		if err != nil {
			continue
		}
		for _, d := range st.detectors {
			if d.Skips(rel) {
				return true
			}
		}
	}
	return false
}

type found struct {
	mu        sync.Mutex
	sites     []*site
	lockfiles []string
	err       error
}

func (s *Scanner) Scan(root string) ([]Component, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", root, err)
	}

	pace := newPacer(s.OpsPerSecond)
	result, err := s.walk(absRoot, pace)
	if err != nil {
		return nil, err
	}
	sort.Slice(result.sites, func(i, j int) bool { return result.sites[i].root < result.sites[j].root })

	siteComponents := make([][]Component, len(result.sites))
	siteLockfiles := make([][]string, len(result.sites))
	s.parallel(len(result.sites), func(i int) {
		siteComponents[i], siteLockfiles[i] = s.scanSite(result.sites[i], pace)
	})

	lockfiles := result.lockfiles
	for _, l := range siteLockfiles {
		lockfiles = append(lockfiles, l...)
	}
	sort.Strings(lockfiles)

	lockComponents := make([][]Component, len(lockfiles))
	s.parallel(len(lockfiles), func(i int) {
		path := lockfiles[i]
		pace.wait()
		packages, err := lockfile.Parse(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", path, err)
			return
		}
		for _, p := range packages {
			lockComponents[i] = append(lockComponents[i], Component{
				Product:   p.Name,
				Version:   p.Version,
				Ecosystem: p.Ecosystem,
				LocalID:   path,
			})
		}
	})

	var components []Component
	for _, c := range siteComponents {
		components = append(components, c...)
	}
	for _, c := range lockComponents {
		components = append(components, c...)
	}
	return components, nil
}

func (s *Scanner) parallel(n int, fn func(i int)) {
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < min(s.workers(), n); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

func (s *Scanner) walk(root string, pace *pacer) (*found, error) {
	res := &found{}
	sem := make(chan struct{}, s.workers())
	var wg sync.WaitGroup

	rootDev, checkDev := uint64(0), false
	if !s.CrossFilesystems {
		if info, err := os.Stat(root); err == nil {
			rootDev, checkDev = deviceOf(info)
		}
	}

	var visit func(dir string, remaining int, in *site)
	visit = func(dir string, remaining int, in *site) {
		defer wg.Done()

		pace.wait()
		sem <- struct{}{}
		if checkDev && dir != root {
			if info, err := os.Lstat(dir); err == nil {
				if dev, ok := deviceOf(info); ok && dev != rootDev {
					<-sem
					return
				}
			}
		}
		entries, err := os.ReadDir(dir)
		var found *site
		var lockfiles []string
		if err == nil {
			names := make(map[string]struct{}, len(entries))
			for _, e := range entries {
				names[e.Name()] = struct{}{}
				if e.Type().IsRegular() && lockfile.IsLockfile(e.Name()) {
					lockfiles = append(lockfiles, filepath.Join(dir, e.Name()))
				}
			}
			found = s.detectedBy(dir, func(name string) bool { _, ok := names[name]; return ok })
		}
		<-sem

		if err != nil {
			s.readFailed(res, dir, root, err)
			return
		}

		res.mu.Lock()
		res.lockfiles = append(res.lockfiles, lockfiles...)
		if found != nil {
			found.entries = entries
			found.parent = in
			res.sites = append(res.sites, found)
			in = found
		}
		res.mu.Unlock()

		// In small mode an install is not descended into: its plugins and their lock files are found by scanSite.
		if remaining == 0 || (found != nil && s.Mode == ModeSmall) {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || skipDirs[e.Name()] {
				continue
			}
			child := filepath.Join(dir, e.Name())
			if s.Mode == ModeHalf && in.skips(child) {
				continue
			}
			wg.Add(1)
			go visit(child, decrementDepth(remaining), in)
		}
	}

	wg.Add(1)
	go visit(root, s.maxDepth, nil)
	wg.Wait()

	return res, res.err
}

func (s *Scanner) readFailed(res *found, dir, root string, err error) {
	if dir != root && (errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist)) {
		fmt.Fprintf(os.Stderr, "warning: skipping unreadable directory %s\n", dir)
		return
	}
	res.mu.Lock()
	defer res.mu.Unlock()
	if res.err == nil {
		res.err = fmt.Errorf("reading %s: %w", dir, err)
	}
}

func decrementDepth(depth int) int {
	if depth < 0 {
		return depth
	}
	return depth - 1
}

func (s *Scanner) detectedBy(path string, has func(string) bool) *site {
	var found *site
	for _, d := range s.registry.All() {
		if d.DetectIn(path, has) {
			if found == nil {
				found = &site{root: path}
			}
			found.detectors = append(found.detectors, d)
		}
	}
	return found
}

// scanSite reads an install's core version and plugins. In small mode it also returns the lock files in the plugin
// directories, which the walk did not enter; the site root's own lock files were already collected by the walk.
func (s *Scanner) scanSite(st *site, pace *pacer) ([]Component, []string) {
	var components []Component
	var lockfiles []string

	ls := detector.NewListing()
	if pace != nil {
		ls.Pace = pace.wait
	}
	ls.Seed(st.root, st.entries)

	for _, d := range st.detectors {
		if version, err := d.CoreVersion(st.root, ls); err == nil {
			components = append(components, Component{
				Vendor:  d.Name,
				Product: d.Name,
				Version: version,
				LocalID: st.root,
			})
		} else {
			fmt.Fprintf(os.Stderr, "warning: %s detected at %s but version unknown\n", d.Name, st.root)
		}

		plugins, err := d.DetectPlugins(st.root, ls)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s plugins at %s: %v\n", d.Name, st.root, err)
			continue
		}

		for _, p := range plugins {
			components = append(components, Component{
				Product:  p.Name,
				Version:  p.Version,
				LocalID:  p.Path,
				Platform: d.Name,
			})
			if s.Mode != ModeSmall {
				continue
			}
			// Usually already listed while looking for the version file, so this is free.
			entries, _ := ls.ReadDir(p.Path)
			for _, e := range entries {
				if e.Type().IsRegular() && lockfile.IsLockfile(e.Name()) {
					lockfiles = append(lockfiles, filepath.Join(p.Path, e.Name()))
				}
			}
		}
	}

	return components, lockfiles
}
