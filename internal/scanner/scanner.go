// Package scanner walks a target path with a detector.Registry and produces
// the list of installed components (CMS cores and their plugins/modules)
// found there.
package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/TadeasDitte/Svetovit/internal/detector"
)

// Component is a single piece of installed software found on disk, identified
// well enough to be checked against a vulnerability database. LocalID is the
// absolute filesystem path of the component (the site root for a CMS core,
// or the plugin/module directory), so results can be traced back to the
// exact installation a tenant with multiple websites has multiple of.
type Component struct {
	Vendor  string
	Product string
	Version string
	LocalID string
}

// Scanner detects installed CMS platforms and plugins/modules under a root path.
type Scanner struct {
	registry *detector.Registry
}

// New creates a Scanner that checks against every detector in registry.
func New(registry *detector.Registry) *Scanner {
	return &Scanner{registry: registry}
}

// Scan looks for CMS installs at root. If root itself isn't a recognized
// install, its immediate subdirectories are checked instead, so a single
// tenant's home directory containing several independent sites (e.g.
// /var/www/p69696/{web1,web2}, each a different CMS) can be scanned in one
// call, with each site's components carrying that site's own path as LocalID.
func (s *Scanner) Scan(root string) ([]Component, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", root, err)
	}

	sites, err := s.discoverSites(absRoot)
	if err != nil {
		return nil, err
	}

	var components []Component
	for _, site := range sites {
		found, err := s.scanSite(site)
		if err != nil {
			return nil, err
		}
		components = append(components, found...)
	}

	return components, nil
}

// discoverSites returns the site root(s) to scan: root itself if a detector
// recognizes it directly, otherwise whichever of its immediate subdirectories do.
func (s *Scanner) discoverSites(root string) ([]string, error) {
	if s.detectedBy(root) != nil {
		return []string{root}, nil
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", root, err)
	}

	var sites []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		siteDir := filepath.Join(root, entry.Name())
		if s.detectedBy(siteDir) != nil {
			sites = append(sites, siteDir)
		}
	}

	return sites, nil
}

func (s *Scanner) detectedBy(path string) *detector.Detector {
	for _, d := range s.registry.All() {
		if d.Detect(path) {
			return d
		}
	}
	return nil
}

// scanSite returns every component found at site, a single CMS install root.
func (s *Scanner) scanSite(site string) ([]Component, error) {
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
		}

		plugins, err := d.DetectPlugins(site)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.Name, err)
		}

		for _, p := range plugins {
			// No vendor mapping table is available for plugins/modules, so the
			// plugin's own directory name is used as both vendor and product.
			// This matches the vendor==product CPE convention for standalone
			// software; anything that doesn't resolve comes back in the API's
			// "unmatched" list rather than failing the scan.
			components = append(components, Component{
				Vendor:  p.Name,
				Product: p.Name,
				Version: p.Version,
				LocalID: p.Path,
			})
		}
	}

	return components, nil
}
