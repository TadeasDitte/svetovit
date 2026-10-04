package lockfile

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func sorted(pkgs []Package) []Package {
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].Name+"@"+pkgs[i].Version < pkgs[j].Name+"@"+pkgs[j].Version
	})
	return pkgs
}

func equal(a, b []Package) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestIsLockfile(t *testing.T) {
	for name, want := range map[string]bool{
		"composer.lock":  true,
		"pnpm-lock.yaml": true,
		"package.json":   false,
		"yarn.lock":      false,
		"":               false,
	} {
		if got := IsLockfile(name); got != want {
			t.Errorf("IsLockfile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParseUnknownFileIsIgnored(t *testing.T) {
	pkgs, err := Parse(writeFile(t, "yarn.lock", "whatever"))
	if err != nil || pkgs != nil {
		t.Fatalf("got %v, %v", pkgs, err)
	}
}

func TestParseMissingFile(t *testing.T) {
	for _, name := range []string{"composer.lock", "pnpm-lock.yaml"} {
		if _, err := Parse(filepath.Join(t.TempDir(), name)); err == nil {
			t.Errorf("%s: expected error for missing file", name)
		}
	}
}

func TestParseComposer(t *testing.T) {
	path := writeFile(t, "composer.lock", `{
  "packages": [
    {"name": "symfony/http-kernel", "version": "v6.4.1"},
    {"name": "monolog/monolog", "version": "3.5.0"},
    {"name": "acme/branch", "version": "dev-main"},
    {"name": "acme/empty", "version": ""},
    {"name": "", "version": "1.0.0"},
    {"name": "symfony/http-kernel", "version": "6.4.1"}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "version": "10.5.0"},
    {"name": "nonamespace", "version": "1.0"}
  ]
}`)
	got, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{EcosystemPackagist, "monolog", "monolog/monolog", "3.5.0"},
		{EcosystemPackagist, "", "nonamespace", "1.0"},
		{EcosystemPackagist, "phpunit", "phpunit/phpunit", "10.5.0"},
		{EcosystemPackagist, "symfony", "symfony/http-kernel", "6.4.1"},
	}
	if !equal(sorted(got), want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestParseComposerInvalidJSON(t *testing.T) {
	_, err := Parse(writeFile(t, "composer.lock", "{not json"))
	if err == nil || !strings.Contains(err.Error(), "parsing") {
		t.Fatalf("got %v", err)
	}
}

func TestParsePnpmKeyFormats(t *testing.T) {
	tests := []struct {
		name    string
		version string
		keys    string
		want    []Package
	}{
		{
			"v5 slash keys", "5.4",
			"  /lodash/4.17.21:\n    resolution: {}\n  /@babel/core/7.23.0_peer@2.0.0:\n    resolution: {}\n",
			[]Package{
				{EcosystemNpm, "@babel", "@babel/core", "7.23.0"},
				{EcosystemNpm, "", "lodash", "4.17.21"},
			},
		},
		{
			"v6 at keys", "'6.0'",
			"  /lodash@4.17.21:\n    resolution: {}\n  /@babel/core@7.23.0(peer@2.0.0):\n    resolution: {}\n",
			[]Package{
				{EcosystemNpm, "@babel", "@babel/core", "7.23.0"},
				{EcosystemNpm, "", "lodash", "4.17.21"},
			},
		},
		{
			"v9 bare keys", "'9.0'",
			"  lodash@4.17.21:\n    resolution: {}\n  '@babel/core@7.23.0':\n    resolution: {}\n  '@babel/core@7.23.0(peer@2.0.0)':\n    resolution: {}\n",
			[]Package{
				{EcosystemNpm, "@babel", "@babel/core", "7.23.0"},
				{EcosystemNpm, "", "lodash", "4.17.21"},
			},
		},
		{
			"non-registry versions are skipped", "'9.0'",
			"  local@link:../local:\n    resolution: {}\n  gh@github.com/x/y:\n    resolution: {}\n  ok@1.0.0:\n    resolution: {}\n",
			[]Package{{EcosystemNpm, "", "ok", "1.0.0"}},
		},
		{
			"malformed keys are skipped", "'9.0'",
			"  noversion:\n    resolution: {}\n  '@scope':\n    resolution: {}\n  ok@1.0.0:\n    resolution: {}\n",
			[]Package{{EcosystemNpm, "", "ok", "1.0.0"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, "pnpm-lock.yaml", "lockfileVersion: "+tt.version+"\npackages:\n"+tt.keys)
			got, err := Parse(path)
			if err != nil {
				t.Fatal(err)
			}
			if !equal(sorted(got), tt.want) {
				t.Fatalf("got %+v\nwant %+v", sorted(got), tt.want)
			}
		})
	}
}

func TestParsePnpmEmptyAndInvalid(t *testing.T) {
	got, err := Parse(writeFile(t, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n"))
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := Parse(writeFile(t, "pnpm-lock.yaml", "packages: [unclosed")); err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}

func TestSplitNamespace(t *testing.T) {
	for in, want := range map[string]string{
		"symfony/console": "symfony",
		"@babel/core":     "@babel",
		"lodash":          "",
		"/odd":            "",
		"a/b/c":           "a/b",
	} {
		if got := splitNamespace(in); got != want {
			t.Errorf("splitNamespace(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInstallableVersion(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3":      "1.2.3",
		"v1.2.3":     "1.2.3",
		" v2.0.0 ":   "2.0.0",
		"dev-main":   "",
		"":           "",
		"v":          "",
		"link:../x":  "",
		"github.com": "",
	} {
		got, ok := installableVersion(in)
		if got != want || ok != (want != "") {
			t.Errorf("installableVersion(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}
