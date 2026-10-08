package system

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func parseDpkgStatus(path string) ([]Package, error) {
	var packages []Package
	err := readStanzas(path, ": ", func(fields map[string]string) {
		if !strings.HasSuffix(fields["Status"], " installed") || fields["Package"] == "" || fields["Version"] == "" {
			return
		}
		name, version := fields["Package"], fields["Version"]
		if source := fields["Source"]; source != "" {
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

var nixStorePath = regexp.MustCompile(`^/nix/store/[0-9a-z]{32}-(.+?)-([0-9][0-9A-Za-z.+_]*)(?:-.*)?$`)

func parseNixClosure(out string) []Package {
	var packages []Package
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, ".drv") || strings.HasSuffix(line, "-source") {
			continue
		}
		m := nixStorePath.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(m[1], "nixos-system") {
			continue
		}
		packages = append(packages, Package{Name: m[1], Version: strings.TrimRight(m[2], ".")})
	}
	return dedupe(packages)
}
