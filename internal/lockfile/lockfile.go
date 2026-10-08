package lockfile

import (
	"path/filepath"
	"strings"
)

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

func IsLockfile(name string) bool {
	_, ok := parsers[name]
	return ok
}

func Parse(path string) ([]Package, error) {
	parse, ok := parsers[filepath.Base(path)]
	if !ok {
		return nil, nil
	}
	return parse(path)
}

func splitNamespace(name string) string {
	if i := strings.LastIndex(name, "/"); i > 0 {
		return name[:i]
	}
	return ""
}

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
