package scanner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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

type Scanner struct {
	registry *detector.Registry
	maxDepth int
	Workers int
}

func New(registry *detector.Registry, maxDepth int) *Scanner {
	return &Scanner{registry: registry, maxDepth: maxDepth}
}

func (s *Scanner) workers() int {
	if s.Workers > 0 {
		return s.Workers
	}
	return min(32, runtime.NumCPU()*4)
}

type found struct {
	mu        sync.Mutex
	sites     []string
	lockfiles []string
	err       error
}

func (s *Scanner) Scan(root string) ([]Component, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", root, err)
	}

	result, err := s.walk(absRoot)
	if err != nil {
		return nil, err
	}
	sort.Strings(result.sites)
	sort.Strings(result.lockfiles)

	siteComponents := make([][]Component, len(result.sites))
	s.parallel(len(result.sites), func(i int) {
		siteComponents[i] = s.scanSite(result.sites[i])
	})

	lockComponents := make([][]Component, len(result.lockfiles))
	s.parallel(len(result.lockfiles), func(i int) {
		path := result.lockfiles[i]
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

func (s *Scanner) walk(root string) (*found, error) {
	res := &found{}
	sem := make(chan struct{}, s.workers())
	var wg sync.WaitGroup

	var visit func(dir string, remaining int, inSite bool)
	visit = func(dir string, remaining int, inSite bool) {
		defer wg.Done()

		sem <- struct{}{}
		entries, err := os.ReadDir(dir)
		var isSite bool
		var lockfiles []string
		if err == nil {
			names := make(map[string]struct{}, len(entries))
			for _, e := range entries {
				names[e.Name()] = struct{}{}
				if e.Type().IsRegular() && lockfile.IsLockfile(e.Name()) {
					lockfiles = append(lockfiles, filepath.Join(dir, e.Name()))
				}
			}
			if !inSite {
				isSite = s.detectedBy(dir, func(name string) bool { _, ok := names[name]; return ok })
			}
		}
		<-sem

		if err != nil {
			s.readFailed(res, dir, root, err)
			return
		}

		res.mu.Lock()
		res.lockfiles = append(res.lockfiles, lockfiles...)
		if isSite {
			res.sites = append(res.sites, dir)
		}
		res.mu.Unlock()

		if remaining == 0 {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || skipDirs[e.Name()] {
				continue
			}
			wg.Add(1)
			go visit(filepath.Join(dir, e.Name()), decrementDepth(remaining), inSite || isSite)
		}
	}

	wg.Add(1)
	go visit(root, s.maxDepth, false)
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

func (s *Scanner) detectedBy(path string, has func(string) bool) bool {
	for _, d := range s.registry.All() {
		if d.DetectIn(path, has) {
			return true
		}
	}
	return false
}

func (s *Scanner) scanSite(site string) []Component {
	var components []Component

	for _, d := range s.registry.All() {
		if !d.Detect(site) {
			continue
		}

		if version, err := d.CoreVersion(site); err == nil {
			components = append(components, Component{
				Vendor:  d.Name,
				Product: d.Name,
				Version: version,
				LocalID: site,
			})
		} else {
			fmt.Fprintf(os.Stderr, "warning: %s detected at %s but version unknown\n", d.Name, site)
		}

		plugins, err := d.DetectPlugins(site)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s plugins at %s: %v\n", d.Name, site, err)
			continue
		}

		for _, p := range plugins {
			components = append(components, Component{
				Product:  p.Name,
				Version:  p.Version,
				LocalID:  p.Path,
				Platform: d.Name,
			})
		}
	}

	return components
}
