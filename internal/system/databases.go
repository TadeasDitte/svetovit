package system

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// parseDpkgStatus reads the dpkg status database. Packages are reported under
// their source package name since that is what Debian/Ubuntu advisories track.
func parseDpkgStatus(path string) ([]Package, error) {
	var packages []Package
	err := readStanzas(path, ": ", func(fields map[string]string) {
		if !strings.HasSuffix(fields["Status"], " installed") || fields["Package"] == "" || fields["Version"] == "" {
			return
		}
		name, version := fields["Package"], fields["Version"]
		if source := fields["Source"]; source != "" {
			// "Source: openssl" or "Source: openssl (3.0.11-1)" when it differs from the binary version.
			sourceName, sourceVersion, hasVersion := strings.Cut(source, " (")
			name = sourceName
			if hasVersion {
				version = strings.TrimSuffix(sourceVersion, ")")
			}
		}
		packages = append(packages, Package{Name: name, Version: version})
	})
	return dedupe(packages), err
}

// parseAPKInstalled reads Alpine's installed database, reporting packages under their origin (source) name.
func parseAPKInstalled(path string) ([]Package, error) {
	var packages []Package
	err := readStanzas(path, ":", func(fields map[string]string) {
		name := fields["o"]
		if name == "" {
			name = fields["P"]
		}
		if name == "" || fields["V"] == "" {
			return
		}
		packages = append(packages, Package{Name: name, Version: fields["V"]})
	})
	return dedupe(packages), err
}

// parsePacmanLocal reads the desc file of every package in pacman's local database.
func parsePacmanLocal(dir string) ([]Package, error) {
	descs, err := filepath.Glob(filepath.Join(dir, "*", "desc"))
	if err != nil {
		return nil, err
	}

	var packages []Package
	for _, desc := range descs {
		data, err := os.ReadFile(desc)
		if err != nil {
			return nil, err
		}
		var name, version, section string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%"):
				section = line
			case line == "":
				section = ""
			case section == "%NAME%":
				name = line
			case section == "%VERSION%":
				version = line
			}
		}
		if name != "" && version != "" {
			packages = append(packages, Package{Name: name, Version: version})
		}
	}
	return packages, nil
}

// readStanzas calls fn for every blank-line separated block of "Key<sep>Value" lines.
// Indented continuation lines are ignored.
func readStanzas(path, sep string, fn func(map[string]string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fields := make(map[string]string)
	flush := func() {
		if len(fields) > 0 {
			fn(fields)
			fields = make(map[string]string)
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if key, value, ok := strings.Cut(line, sep); ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	flush()
	return sc.Err()
}

func dedupe(packages []Package) []Package {
	seen := make(map[Package]bool, len(packages))
	out := packages[:0]
	for _, p := range packages {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
