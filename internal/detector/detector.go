// Package detector identifies CMS platforms and their installed plugins/modules
// on a filesystem path, extracting version strings via configurable markers and regexes.
package detector

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// VersionSpec describes where to find a version string: a file relative to the
// scan root, and a regex whose first capture group is the version.
type VersionSpec struct {
	File  string `yaml:"file"`
	Regex string `yaml:"regex"`
}

// PluginSpec describes how to discover installed plugins/modules for a CMS:
// a glob (relative to the scan root) matching one directory per plugin, and
// how to extract that plugin's version from a file inside its directory.
type PluginSpec struct {
	Glob         string `yaml:"glob"`
	VersionFile  string `yaml:"version_file"`
	VersionRegex string `yaml:"version_regex"`
}

// Detector describes how to recognize a CMS/platform and enumerate its
// installed version and plugins/modules from a config file (see detectors/*.yml).
type Detector struct {
	Name    string      `yaml:"name"`
	Markers []string    `yaml:"markers"`
	Version VersionSpec `yaml:"version"`
	Plugins PluginSpec  `yaml:"plugins"`
}

// Plugin is a single detected plugin/module and its version.
type Plugin struct {
	Name    string
	Version string
	Path    string
}

// Detect reports whether root contains any of the detector's marker files,
// i.e. whether this platform appears to be installed at root.
func (d *Detector) Detect(root string) bool {
	for _, marker := range d.Markers {
		if _, err := os.Stat(filepath.Join(root, marker)); err == nil {
			return true
		}
	}
	return false
}

// CoreVersion extracts the platform's own version string from root.
func (d *Detector) CoreVersion(root string) (string, error) {
	if d.Version.File == "" {
		return "", fmt.Errorf("%s: no version file configured", d.Name)
	}
	return extractVersion(filepath.Join(root, d.Version.File), d.Version.Regex)
}

// DetectPlugins enumerates installed plugins/modules under root, skipping any
// whose version cannot be determined.
func (d *Detector) DetectPlugins(root string) ([]Plugin, error) {
	if d.Plugins.Glob == "" {
		return nil, nil
	}

	matches, err := filepath.Glob(filepath.Join(root, d.Plugins.Glob))
	if err != nil {
		return nil, fmt.Errorf("%s: invalid plugin glob: %w", d.Name, err)
	}

	var plugins []Plugin
	for _, dir := range matches {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}

		version, err := extractVersion(filepath.Join(dir, d.Plugins.VersionFile), d.Plugins.VersionRegex)
		if err != nil {
			continue
		}

		plugins = append(plugins, Plugin{
			Name:    filepath.Base(dir),
			Version: version,
			Path:    dir,
		})
	}

	return plugins, nil
}

func extractVersion(path, pattern string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid version regex %q: %w", pattern, err)
	}

	match := re.FindSubmatch(data)
	if len(match) < 2 {
		return "", fmt.Errorf("no version match in %s", path)
	}

	return string(match[1]), nil
}
