package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
)

type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parseComposer reads a composer.lock. Dev packages are included since the lock
// file can't tell whether they were installed with --no-dev.
func parseComposer(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var packages []Package
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		version, ok := installableVersion(p.Version)
		if p.Name == "" || !ok {
			continue
		}
		packages = append(packages, Package{
			Ecosystem: EcosystemPackagist,
			Namespace: splitNamespace(p.Name),
			Name:      p.Name,
			Version:   version,
		})
	}

	return dedupe(packages), nil
}
