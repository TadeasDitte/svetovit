// Package lockfile extracts installed dependency versions from package manager lock files.
package lockfile

import (
	"path/filepath"
	"strings"
)

// Package is a single dependency pinned by a lock file. Name is the full package
// name as the ecosystem knows it (e.g. "symfony/http-kernel" or "@babel/core"),
// Namespace is its vendor/scope part if it has one.
type Package struct {
	Ecosystem string
	Namespace string
	Name      string
	Version   string
}

const (
	EcosystemPackagist = "Packagist"
	EcosystemNpm       = "npm"
)

type parser func(path string) ([]Package, error)

var parsers = map[string]parser{
	"composer.lock":  parseComposer,
	"pnpm-lock.yaml": parsePnpm,
}

// IsLockfile reports whether the file name is a lock file this package can parse.
func IsLockfile(name string) bool {
	_, ok := parsers[name]
	return ok
}

// Parse reads the lock file at path, picking the parser by its file name.
func Parse(path string) ([]Package, error) {
	parse, ok := parsers[filepath.Base(path)]
	if !ok {
		return nil, nil
	}
	return parse(path)
}

// splitNamespace returns the "vendor" of "vendor/name" (or "@scope" of "@scope/name"); names without a slash have none.
func splitNamespace(name string) string {
	if i := strings.LastIndex(name, "/"); i > 0 {
		return name[:i]
	}
	return ""
}

// installableVersion drops versions that don't point at a released package (branches, paths, URLs).
func installableVersion(version string) (string, bool) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if version == "" || version[0] < '0' || version[0] > '9' {
		return "", false
	}
	return version, true
}

func dedupe(packages []Package) []Package {
	seen := make(map[Package]bool, len(packages))
	out := packages[:0]
	for _, p := range packages {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
