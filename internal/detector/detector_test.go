package detector

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func load(t *testing.T, yml string) *Detector {
	t.Helper()
	reg, err := LoadFS(fstest.MapFS{"d.yml": {Data: []byte(yml)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.All()) != 1 {
		t.Fatalf("got %d detectors, want 1", len(reg.All()))
	}
	return reg.All()[0]
}

const testDetector = `
name: demo
markers:
  - demo.php
  - sub/marker.txt
version:
  - file: VERSION
    regex: 'v=(\d+\.\d+)'
  - file: "*.info"
    regex: 'version: (\S+)'
plugins:
  - glob: "plugins/*"
    version:
      - file: "*.php"
        regex: 'Version: (\S+)'
      - file: readme.txt
        regex: 'Stable tag: (\S+)'
`

func TestLoadFSErrors(t *testing.T) {
	tests := []struct {
		name string
		yml  string
		want string
	}{
		{"missing name", "markers: [a]\n", `missing required "name"`},
		{"no markers", "name: x\n", "no markers"},
		{"bad yaml", "name: [", "parsing"},
		{"version missing file", "name: x\nmarkers: [a]\nversion:\n  - regex: '(1)'\n", "missing file"},
		{"bad skip glob", "name: x\nmarkers: [a]\nskip: ['[']\n", "skip[0]: invalid glob"},
		{"bad regex", "name: x\nmarkers: [a]\nversion:\n  - file: f\n    regex: '(['\n", "invalid version regex"},
		{"no capture group", "name: x\nmarkers: [a]\nversion:\n  - file: f\n    regex: 'abc'\n", "needs a capture group"},
		{"plugin missing glob", "name: x\nmarkers: [a]\nplugins:\n  - version: [{file: f, regex: '(1)'}]\n", "missing glob"},
		{"plugin bad glob", "name: x\nmarkers: [a]\nplugins:\n  - glob: '['\n    version: [{file: f, regex: '(1)'}]\n", "invalid glob"},
		{"plugin no version", "name: x\nmarkers: [a]\nplugins:\n  - glob: 'p/*'\n", "no version sources"},
		{"plugin bad regex", "name: x\nmarkers: [a]\nplugins:\n  - glob: 'p/*'\n    version: [{file: f, regex: '(['}]\n", "plugins[0].version[0]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadFS(fstest.MapFS{"d.yml": {Data: []byte(tt.yml)}})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadFSSkipsNonYAMLAndDirs(t *testing.T) {
	reg, err := LoadFS(fstest.MapFS{
		"a.yml":         {Data: []byte("name: a\nmarkers: [x]\n")},
		"b.yaml":        {Data: []byte("name: b\nmarkers: [y]\n")},
		"README.md":     {Data: []byte("not yaml: [")},
		"nested/c.yml":  {Data: []byte("name: c\nmarkers: [z]\n")},
		"notes.yml.bak": {Data: []byte("garbage: [")},
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range reg.All() {
		names = append(names, d.Name)
	}
	if !reflect.DeepEqual(names, []string{"a", "b"}) {
		t.Fatalf("got %v, want [a b]", names)
	}
}

func TestDetectIn(t *testing.T) {
	d := load(t, testDetector)
	root := t.TempDir()
	write(t, filepath.Join(root, "sub/marker.txt"), "")

	var asked []string
	has := func(name string) bool {
		asked = append(asked, name)
		return name == "sub"
	}
	if !d.DetectIn(root, has) {
		t.Fatal("expected detection through first path segment")
	}
	if !reflect.DeepEqual(asked, []string{"demo.php", "sub"}) {
		t.Errorf("has asked about %v", asked)
	}

	other := t.TempDir()
	write(t, filepath.Join(other, "sub/other.txt"), "")
	if d.DetectIn(other, func(name string) bool { return name == "sub" }) {
		t.Error("marker file is missing, should not be detected")
	}
	if !d.DetectIn(t.TempDir(), func(name string) bool { return name == "demo.php" }) {
		t.Error("listed top-level marker should be detected without a stat")
	}
	if d.DetectIn(root, func(string) bool { return false }) {
		t.Error("nothing listed, should not be detected")
	}
}

func TestCoreVersion(t *testing.T) {
	d := load(t, testDetector)

	t.Run("first source wins", func(t *testing.T) {
		root := t.TempDir()
		write(t, filepath.Join(root, "VERSION"), "v=1.2")
		write(t, filepath.Join(root, "x.info"), "version: 9.9")
		got, err := d.CoreVersion(root, NewListing())
		if err != nil || got != "1.2" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("falls back to glob source", func(t *testing.T) {
		root := t.TempDir()
		write(t, filepath.Join(root, "VERSION"), "no version here")
		write(t, filepath.Join(root, "x.info"), "version: 9.9")
		got, err := d.CoreVersion(root, NewListing())
		if err != nil || got != "9.9" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("none found", func(t *testing.T) {
		if _, err := d.CoreVersion(t.TempDir(), NewListing()); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestDetectPlugins(t *testing.T) {
	d := load(t, testDetector)
	root := t.TempDir()
	write(t, filepath.Join(root, "plugins/alpha/alpha.php"), "<?php\n// Version: 2.0\n")
	write(t, filepath.Join(root, "plugins/beta/readme.txt"), "Stable tag: 3.1\n")
	write(t, filepath.Join(root, "plugins/gamma/readme.txt"), "nothing useful")
	write(t, filepath.Join(root, "plugins/stray.php"), "Version: 5") // a file, not a directory

	got, err := d.DetectPlugins(root, NewListing())
	if err != nil {
		t.Fatal(err)
	}
	want := []Plugin{
		{Name: "alpha", Version: "2.0", Path: filepath.Join(root, "plugins/alpha")},
		{Name: "beta", Version: "3.1", Path: filepath.Join(root, "plugins/beta")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDetectPluginsReadsEachDirectoryOnce(t *testing.T) {
	// modules/* and modules/*/* both visit modules/contrib; the second pass must come from the cache.
	d := load(t, "name: x\nmarkers: [a]\nplugins:\n"+
		"  - glob: 'modules/*'\n    version: [{file: '*.info.yml', regex: 'version: (\\S+)'}]\n"+
		"  - glob: 'modules/*/*'\n    version: [{file: '*.info.yml', regex: 'version: (\\S+)'}]\n")
	root := t.TempDir()
	write(t, filepath.Join(root, "modules/contrib/foo/foo.info.yml"), "version: 1.0")
	ls := NewListing()
	got, err := d.DetectPlugins(root, ls)
	if err != nil || len(got) != 1 || got[0].Name != "foo" {
		t.Fatalf("got %+v, %v", got, err)
	}
	// Once cached, a listing is served even after the directory is gone.
	if err := os.RemoveAll(filepath.Join(root, "modules")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"modules", "modules/contrib", "modules/contrib/foo"} {
		if entries, err := ls.ReadDir(filepath.Join(root, dir)); err != nil || len(entries) == 0 {
			t.Errorf("%s not cached: %v", dir, err)
		}
	}
}

func TestExpandTriesFileNamedAfterDirFirst(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bar")
	write(t, filepath.Join(dir, "a.php"), "")
	write(t, filepath.Join(dir, "bar.php"), "")
	write(t, filepath.Join(dir, "z.php"), "")
	got := expand(dir, "*.php", NewListing())
	want := []string{filepath.Join(dir, "bar.php"), filepath.Join(dir, "a.php"), filepath.Join(dir, "z.php")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := expand(dir, "readme.txt", NewListing()); len(got) != 0 {
		t.Fatalf("absent file should not be returned: %v", got)
	}
}

func TestDetectPluginsNoneInstalled(t *testing.T) {
	d := load(t, testDetector)
	got, err := d.DetectPlugins(t.TempDir(), NewListing())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestGlobCharactersInDirAreLiteral(t *testing.T) {
	d := load(t, testDetector)
	root := filepath.Join(t.TempDir(), "site[1]")
	write(t, filepath.Join(root, "x.info"), "version: 4.0")
	got, err := d.CoreVersion(root, NewListing())
	if err != nil || got != "4.0" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestExtractVersionOnlyReadsFileHeader(t *testing.T) {
	d := load(t, "name: x\nmarkers: [a]\nversion:\n  - file: f\n    regex: 'v=(\\d+)'\n")
	root := t.TempDir()
	write(t, filepath.Join(root, "f"), strings.Repeat(" ", maxVersionRead)+"v=7")
	if _, err := d.CoreVersion(root, NewListing()); err == nil {
		t.Fatal("version beyond the read cap should not be found")
	}
	write(t, filepath.Join(root, "f"), strings.Repeat(" ", maxVersionRead-10)+"v=7")
	if got, err := d.CoreVersion(root, NewListing()); err != nil || got != "7" {
		t.Fatalf("got %q, %v", got, err)
	}
}
func TestSkips(t *testing.T) {
	d := load(t, "name: x\nmarkers: [a]\nskip:\n  - uploads\n  - sites/*/files\n")
	for rel, want := range map[string]bool{
		"uploads": true,
		filepath.FromSlash("sites/default/files"): true,
		filepath.FromSlash("sites/default"):       false,
		filepath.FromSlash("uploads/2024"):        false, // never reached: the walk stops at uploads
		"themes":                                  false,
	} {
		if got := d.Skips(rel); got != want {
			t.Errorf("Skips(%q) = %v, want %v", rel, got, want)
		}
	}
}
