package detector

import (
	"fmt"
	"io"
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

func (d *Detector) Detect(root string) bool {
	for _, marker := range d.Markers {
		if _, err := os.Stat(filepath.Join(root, marker)); err == nil {
			return true
		}
	}
	return false
}

func (d *Detector) CoreVersion(root string) (string, error) {
	if version, ok := findVersion(root, d.Version); ok {
		return version, nil
	}
	return "", fmt.Errorf("%s: no version found", d.Name)
}

func (d *Detector) DetectPlugins(root string) ([]Plugin, error) {
	var plugins []Plugin
	for _, spec := range d.Plugins {
		matches, err := filepath.Glob(filepath.Join(root, spec.Glob))
		if err != nil {
			return nil, fmt.Errorf("%s: invalid plugin glob: %w", d.Name, err)
		}

		for _, dir := range matches {
			info, err := os.Stat(dir)
			if err != nil || !info.IsDir() {
				continue
			}

			version, ok := findVersion(dir, spec.Version)
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

func findVersion(dir string, specs []VersionSpec) (string, bool) {
	for _, spec := range specs {
		for _, path := range expand(dir, spec.File) {
			if version, err := extractVersion(path, spec.re); err == nil {
				return version, true
			}
		}
	}
	return "", false
}

func expand(dir, pattern string) []string {
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{filepath.Join(dir, pattern)}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ok, _ := filepath.Match(pattern, e.Name()); ok {
			paths = append(paths, filepath.Join(dir, e.Name()))
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

	data, err := io.ReadAll(io.LimitReader(f, maxVersionRead))
	if err != nil {
		return "", err
	}

	match := re.FindSubmatch(data)
	if len(match) < 2 {
		return "", fmt.Errorf("no version match in %s", path)
	}

	return string(match[1]), nil
}

func (d *Detector) Skips(rel string) bool {
	for _, pattern := range d.Skip {
		if ok, _ := filepath.Match(pattern, rel); ok {
			return true
		}
	}
	return false
}

func (d *Detector) DetectIn(root string, has func(name string) bool) bool {
	for _, marker := range d.Markers {
		first, _, _ := strings.Cut(filepath.ToSlash(marker), "/")
		if !has(first) {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, marker)); err == nil {
			return true
		}
	}
	return false
}
