package detector

import (
	"fmt"
	"io/fs"
	"strings"

	"gopkg.in/yaml.v3"
)


type Registry struct {
	detectors []*Detector
}


func (r *Registry) All() []*Detector {
	return r.detectors
}


func LoadFS(fsys fs.FS) (*Registry, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("reading detector configs: %w", err)
	}

	reg := &Registry{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}

		var d Detector
		if err := yaml.Unmarshal(data, &d); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		if d.Name == "" {
			return nil, fmt.Errorf("%s: missing required \"name\" field", name)
		}

		reg.detectors = append(reg.detectors, &d)
	}

	return reg, nil
}
