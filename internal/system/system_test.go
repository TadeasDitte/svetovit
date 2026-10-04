package system

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestManagerFor(t *testing.T) {
	tests := []struct {
		families []string
		want     Manager
	}{
		{[]string{"debian"}, Dpkg},
		{[]string{"ubuntu", "debian"}, Dpkg},
		{[]string{"linuxmint", "ubuntu", "debian"}, Dpkg},
		{[]string{"rocky", "rhel", "centos", "fedora"}, RPM},
		{[]string{"opensuse-tumbleweed"}, RPM},
		{[]string{"amzn"}, RPM},
		{[]string{"alpine"}, APK},
		{[]string{"manjaro", "arch"}, Pacman},
		{[]string{"nixos"}, Nix},
		{[]string{"gentoo"}, ""},
		{nil, ""},
	}
	for _, tt := range tests {
		if got := managerFor(tt.families); got != tt.want {
			t.Errorf("managerFor(%v) = %q, want %q", tt.families, got, tt.want)
		}
	}
}

func TestEcosystemFor(t *testing.T) {
	tests := []struct{ id, version, want string }{
		{"debian", "12", "Debian:12"},
		{"debian", "12.5", "Debian:12"},
		{"ubuntu", "22.04", "Ubuntu:22.04:LTS"},
		{"ubuntu", "24.04", "Ubuntu:24.04:LTS"},
		{"ubuntu", "23.04", "Ubuntu:23.04"},
		{"ubuntu", "23.10", "Ubuntu:23.10"},
		{"alpine", "3.19.1", "Alpine:v3.19"},
		{"alpine", "3.19", "Alpine:v3.19"},
		{"alpine", "3", "Alpine:v3"},
		{"rocky", "9.3", "Rocky Linux:9"},
		{"almalinux", "8.9", "AlmaLinux:8"},
		{"rhel", "9.3", "Red Hat"},
		{"arch", "", "Arch Linux"},
		{"nixos", "26.11", ""},
		{"fedora", "40", "fedora:40"},
		{"gentoo", "", "gentoo"},
	}
	for _, tt := range tests {
		if got := ecosystemFor(tt.id, tt.version); got != tt.want {
			t.Errorf("ecosystemFor(%q, %q) = %q, want %q", tt.id, tt.version, got, tt.want)
		}
	}
}

func TestEnvironmentSource(t *testing.T) {
	for m, want := range map[Manager]string{
		Dpkg:   dpkgStatus,
		APK:    apkInstalled,
		Pacman: pacmanLocalDB,
		Nix:    nixSystem,
		RPM:    "rpm",
		BSDPkg: "pkg",
	} {
		if got := (&Environment{Manager: m}).Source(); got != want {
			t.Errorf("Source() for %s = %q, want %q", m, got, want)
		}
	}
}

func TestPackagesUnsupportedManager(t *testing.T) {
	_, err := (&Environment{}).Packages()
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v, want ErrUnsupported", err)
	}
}

func TestParseDpkgStatus(t *testing.T) {
	path := writeFile(t, filepath.Join(t.TempDir(), "status"), `Package: libssl3
Status: install ok installed
Version: 3.0.11-1~deb12u2
Source: openssl (3.0.11-1)
Description: Secure Sockets Layer toolkit
 continuation line: ignored

Package: openssl
Status: install ok installed
Version: 3.0.11-1~deb12u2
Source: openssl

Package: bash
Status: install ok installed
Version: 5.2.15-2

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: no-version
Status: install ok installed

Package: libssl3
Status: install ok installed
Version: 3.0.11-1~deb12u2
Source: openssl (3.0.11-1)
`)
	got, err := parseDpkgStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{"openssl", "3.0.11-1"},
		{"openssl", "3.0.11-1~deb12u2"},
		{"bash", "5.2.15-2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestParseDpkgStatusMissingFile(t *testing.T) {
	if _, err := parseDpkgStatus(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseAPKInstalled(t *testing.T) {
	path := writeFile(t, filepath.Join(t.TempDir(), "installed"), `C:Q1abc=
P:libcrypto3
V:3.1.4-r5
o:openssl

P:busybox
V:1.36.1-r15

P:novers

P:musl
V:1.2.4-r2
o:musl

P:musl-utils
V:1.2.4-r2
o:musl
`)
	got, err := parseAPKInstalled(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{"openssl", "3.1.4-r5"},
		{"busybox", "1.36.1-r15"},
		{"musl", "1.2.4-r2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestParsePacmanLocal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "bash-5.2.015-1", "desc"), "%NAME%\nbash\n\n%VERSION%\n5.2.015-1\n\n%DESC%\nThe GNU shell\n")
	writeFile(t, filepath.Join(dir, "glibc-2.38-5", "desc"), "%NAME%\nglibc\n\n%VERSION%\n2.38-5\n")
	writeFile(t, filepath.Join(dir, "broken-1", "desc"), "%NAME%\nbroken\n")
	writeFile(t, filepath.Join(dir, "ALPM_DB_VERSION"), "9\n") // a file, not a package dir

	got, err := parsePacmanLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{{"bash", "5.2.015-1"}, {"glibc", "2.38-5"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestParsePacmanLocalEmpty(t *testing.T) {
	got, err := parsePacmanLocal(t.TempDir())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestReadStanzasIgnoresContinuationAndTrims(t *testing.T) {
	path := writeFile(t, filepath.Join(t.TempDir(), "f"), "A: 1  \n indented: skipped\n\t tab: skipped\nB: two: parts\n\n\n\nA: 3\n")
	var got []map[string]string
	if err := readStanzas(path, ": ", func(m map[string]string) { got = append(got, m) }); err != nil {
		t.Fatal(err)
	}
	want := []map[string]string{{"A": "1", "B": "two: parts"}, {"A": "3"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestDedupe(t *testing.T) {
	in := []Package{{"a", "1"}, {"b", "1"}, {"a", "1"}, {"a", "2"}}
	want := []Package{{"a", "1"}, {"b", "1"}, {"a", "2"}}
	if got := dedupe(in); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseNixClosureEdgeCases(t *testing.T) {
	const h = "/nix/store/3ppjkfrmkr0s0c74hs4ddmld3c9cqkzr-"
	in := "\n  " + h + "zlib-1.3.1  \n" +
		h + "libfoo-1.2.\n" + // trailing dot trimmed
		"/nix/store/short-hash-pkg-1.0\n" + // not a 32 char hash
		"not a store path\n"
	want := []Package{{"zlib", "1.3.1"}, {"libfoo", "1.2"}}
	if got := parseNixClosure(in); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestStderrOf(t *testing.T) {
	if got := stderrOf(errors.New("plain")); got != "" {
		t.Errorf("non-exec error: got %q", got)
	}

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	_, err = exec.Command(sh, "-c", "echo boom >&2; exit 3").Output()
	if got := stderrOf(err); got != ": boom" {
		t.Errorf("got %q, want %q", got, ": boom")
	}
	_, err = exec.Command(sh, "-c", "exit 3").Output()
	if got := stderrOf(err); got != "" {
		t.Errorf("empty stderr: got %q", got)
	}
}

func TestNixCPEsEmptyInputSkipsNix(t *testing.T) {
	got, err := NixCPEs(nil)
	if err != nil || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestQueryTabSeparated(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	script := `printf 'bash\t0:5.2-1\nopenssl\t1:3.0-2\nbad line\n\t1.0\nnoversion\t\n'`
	got, err := queryTabSeparated(sh, "-c", script)
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{{"bash", "5.2-1"}, {"openssl", "1:3.0-2"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	_, err = queryTabSeparated(sh, "-c", "exit 1")
	if err == nil || !strings.Contains(err.Error(), "running") {
		t.Errorf("got %v", err)
	}
}
