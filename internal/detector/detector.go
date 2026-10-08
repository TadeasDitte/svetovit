package detector

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxVersionRead = 64 << 10

type VersionSpec struct {
	File  string `yaml:"file"`
	Regex string `yaml:"regex"`

	re *regexp.Regexp
}

type PluginSpec struct {
	Glob    string        `yaml:"glob"`
	Version []VersionSpec `yaml:"version"`
}

type Detector struct {
	Name    string        `yaml:"name"`
	Markers []string      `yaml:"markers"`
	Version []VersionSpec `yaml:"version"`
	Plugins []PluginSpec  `yaml:"plugins"`
	// Skip lists directories below the install root that the walk never enters in half mode (uploads, caches).
	Skip []string `yaml:"skip"`
}

type Plugin struct {
	Name    string
	Version string
	Path    string
}

func (d *Detector) compile() error {
	if len(d.Markers) == 0 {
		return fmt.Errorf("%s: no markers defined", d.Name)
	}
	if err := compileSpecs(d.Name, "version", d.Version); err != nil {
		return err
	}
	for i, pattern := range d.Skip {
		pattern = filepath.FromSlash(pattern)
		if _, err := filepath.Match(pattern, ""); err != nil {
			return fmt.Errorf("%s: skip[%d]: invalid glob: %w", d.Name, i, err)
		}
		d.Skip[i] = pattern
	}
	for i, p := range d.Plugins {
		if p.Glob == "" {
			return fmt.Errorf("%s: plugins[%d]: missing glob", d.Name, i)
		}
		if _, err := filepath.Match(p.Glob, ""); err != nil {
			return fmt.Errorf("%s: plugins[%d]: invalid glob: %w", d.Name, i, err)
		}
		if len(p.Version) == 0 {
			return fmt.Errorf("%s: plugins[%d]: no version sources", d.Name, i)
		}
		if err := compileSpecs(d.Name, fmt.Sprintf("plugins[%d].version", i), p.Version); err != nil {
			return err
		}
	}
	return nil
}

func compileSpecs(name, field string, specs []VersionSpec) error {
	for i := range specs {
		spec := &specs[i]
		if spec.File == "" {
			return fmt.Errorf("%s: %s[%d]: missing file", name, field, i)
		}
		re, err := regexp.Compile(spec.Regex)
		if err != nil {
			return fmt.Errorf("%s: %s[%d]: invalid version regex %q: %w", name, field, i, spec.Regex, err)
		}
		if re.NumSubexp() < 1 {
			return fmt.Errorf("%s: %s[%d]: version regex %q needs a capture group", name, field, i, spec.Regex)
		}
		spec.re = re
	}
	return nil
}

func (d *Detector) CoreVersion(root string, ls *Listing) (string, error) {
	if version, ok := findVersion(root, d.Version, ls); ok {
		return version, nil
	}
	return "", fmt.Errorf("%s: no version found", d.Name)
}

func (d *Detector) DetectPlugins(root string, ls *Listing) ([]Plugin, error) {
	var plugins []Plugin
	for _, spec := range d.Plugins {
		for _, dir := range globDirs(root, spec.Glob, ls) {
			version, ok := findVersion(dir, spec.Version, ls)
			if !ok {
				continue
			}

			plugins = append(plugins, Plugin{
				Name:    filepath.Base(dir),
				Version: version,
				Path:    dir,
			})
		}
	}

	return plugins, nil
}

// globDirs matches pattern below root against cached listings and returns only directories, in lexical order.
func globDirs(root, pattern string, ls *Listing) []string {
	dirs := []string{root}
	for _, part := range strings.Split(filepath.ToSlash(pattern), "/") {
		var next []string
		for _, dir := range dirs {
			entries, err := ls.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if ok, _ := filepath.Match(part, e.Name()); ok && isDir(dir, e) {
					next = append(next, filepath.Join(dir, e.Name()))
				}
			}
		}
		dirs = next
	}
	return dirs
}

// isDir trusts the dirent type and only stats symlinks, which may point at a directory.
func isDir(parent string, e fs.DirEntry) bool {
	if e.Type()&fs.ModeSymlink == 0 {
		return e.IsDir()
	}
	info, err := os.Stat(filepath.Join(parent, e.Name()))
	return err == nil && info.IsDir()
}

func findVersion(dir string, specs []VersionSpec, ls *Listing) (string, bool) {
	for _, spec := range specs {
		for _, path := range expand(dir, spec.File, ls) {
			ls.pace()
			if version, err := extractVersion(path, spec.re); err == nil {
				return version, true
			}
		}
	}
	return "", false
}

// expand resolves a version source against dir. A name directly in dir is checked against the cached listing, so
// absent files are never opened. A glob tries the file named after dir first (foo/foo.php, foo/foo.info.yml), as
// that is where an extension's manifest usually lives, which saves reading every other match.
func expand(dir, pattern string, ls *Listing) []string {
	if strings.ContainsRune(filepath.ToSlash(pattern), '/') {
		return []string{filepath.Join(dir, pattern)}
	}
	entries, err := ls.ReadDir(dir)
	if err != nil {
		return nil
	}
	preferred := ""
	if rest, ok := strings.CutPrefix(pattern, "*"); ok && !strings.ContainsAny(rest, "*?[") {
		preferred = filepath.Base(dir) + rest
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ok, _ := filepath.Match(pattern, e.Name()); !ok {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if e.Name() == preferred {
			paths = append([]string{path}, paths...)
		} else {
			paths = append(paths, path)
		}
	}
	return paths
}

func extractVersion(path string, re *regexp.Regexp) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// One read of the whole header instead of io.ReadAll's growing buffer.
	buf := make([]byte, maxVersionRead)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", err
	}

	match := re.FindSubmatch(buf[:n])
	if len(match) < 2 {
		return "", fmt.Errorf("no version match in %s", path)
	}

	return string(match[1]), nil
}

// DetectIn reports whether root is an install. has says whether a name is in root's listing: a marker directly in
// root needs no further I/O, a nested one is stat-ed only when its first segment is listed.
func (d *Detector) DetectIn(root string, has func(name string) bool) bool {
	for _, marker := range d.Markers {
		first, _, nested := strings.Cut(filepath.ToSlash(marker), "/")
		if !has(first) {
			continue
		}
		if !nested {
			return true
		}
		if _, err := os.Stat(filepath.Join(root, marker)); err == nil {
			return true
		}
	}
	return false
}

func (d *Detector) Skips(rel string) bool {
	for _, pattern := range d.Skip {
		if ok, _ := filepath.Match(pattern, rel); ok {
			return true
		}
	}
	return false
}
