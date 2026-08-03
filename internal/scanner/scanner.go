package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/TadeasDitte/Svetovit/internal/detector"
)

type Component struct {
	Vendor  string
	Product string
	Version string
	LocalID string
}

const UnlimitedDepth = -1

type Scanner struct {
	registry *detector.Registry
	maxDepth int
}

func New(registry *detector.Registry, maxDepth int) *Scanner {
	return &Scanner{registry: registry, maxDepth: maxDepth}
}

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

func (s *Scanner) discoverSites(root string) ([]string, error) {
	if s.detectedBy(root) != nil {
		return []string{root}, nil
	}
	if s.maxDepth == 0 {
		return nil, nil
	}
	return s.discoverSitesBelow(root, decrementDepth(s.maxDepth))
}

func (s *Scanner) discoverSitesBelow(root string, remainingDepth int) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", root, err)
	}

	var sites []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		if s.detectedBy(dir) != nil {
			sites = append(sites, dir)
			continue
		}
		if remainingDepth == 0 {
			continue
		}
		nested, err := s.discoverSitesBelow(dir, decrementDepth(remainingDepth))
		if err != nil {
			return nil, err
		}
		sites = append(sites, nested...)
	}

	return sites, nil
}

func decrementDepth(depth int) int {
	if depth < 0 {
		return depth
	}
	return depth - 1
}

func (s *Scanner) detectedBy(path string) *detector.Detector {
	for _, d := range s.registry.All() {
		if d.Detect(path) {
			return d
		}
	}
	return nil
}

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
