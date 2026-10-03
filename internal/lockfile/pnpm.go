package lockfile

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type pnpmLock struct {
	LockfileVersion string               `yaml:"lockfileVersion"`
	Packages        map[string]yaml.Node `yaml:"packages"`
}

// parsePnpm reads a pnpm-lock.yaml. Package keys changed format across lockfile versions:
//
//	v5:  /name/1.0.0, /@scope/name/1.0.0_peer@2.0.0
//	v6:  /name@1.0.0, /@scope/name@1.0.0(peer@2.0.0)
//	v9:  name@1.0.0,  @scope/name@1.0.0
func parsePnpm(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock pnpmLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	slashKeys := strings.HasPrefix(lock.LockfileVersion, "5")

	var packages []Package
	for key := range lock.Packages {
		name, rawVersion, ok := splitPnpmKey(key, slashKeys)
		if !ok {
			continue
		}
		version, ok := installableVersion(rawVersion)
		if !ok {
			continue
		}
		packages = append(packages, Package{
			Ecosystem: EcosystemNpm,
			Namespace: splitNamespace(name),
			Name:      name,
			Version:   version,
		})
	}

	return dedupe(packages), nil
}

func splitPnpmKey(key string, slashKeys bool) (name, version string, ok bool) {
	key = strings.TrimPrefix(key, "/")

	if slashKeys {
		i := strings.LastIndex(key, "/")
		if i <= 0 {
			return "", "", false
		}
		name, version = key[:i], key[i+1:]
		if j := strings.Index(version, "_"); j >= 0 {
			version = version[:j]
		}
		return name, version, true
	}

	if i := strings.Index(key, "("); i >= 0 {
		key = key[:i]
	}
	i := strings.LastIndex(key, "@")
	if i <= 0 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}
