package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/TadeasDitte/Svetovit/internal/report"
	"github.com/TadeasDitte/Svetovit/internal/rozhanitsy"
)

func TestParseSections(t *testing.T) {
	tests := []struct {
		in       string
		want     report.Sections
		wantNorm string
	}{
		{"", report.Sections{Bounded: true, Unbound: true}, "all"},
		{"all", report.Sections{Bounded: true, Unbound: true}, "all"},
		{"  ALL ", report.Sections{Bounded: true, Unbound: true}, "all"},
		{"bounded", report.Sections{Bounded: true}, "bounded"},
		{"Unbound", report.Sections{Unbound: true}, "unbound"},
	}
	for _, tt := range tests {
		got, norm, err := parseSections(tt.in)
		if err != nil || got != tt.want || norm != tt.wantNorm {
			t.Errorf("parseSections(%q) = %+v, %q, %v", tt.in, got, norm, err)
		}
	}

	_, _, err := parseSections("bogus")
	if err == nil || !strings.Contains(err.Error(), `"bogus"`) {
		t.Errorf("expected error naming the bad value, got %v", err)
	}
}

func TestWriteReportFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	err := writeReportFile(path, func(w io.Writer) error {
		_, err := io.WriteString(w, "hello")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "hello" {
		t.Errorf("file contains %q", data)
	}

	want := errors.New("write failed")
	if got := writeReportFile(path, func(io.Writer) error { return want }); !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	err = writeReportFile(filepath.Join(t.TempDir(), "missing", "out.txt"), func(io.Writer) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "creating") {
		t.Errorf("got %v", err)
	}
}

func TestParseDays(t *testing.T) {
	tests := map[string]time.Duration{
		"":     0,
		"7d":   7 * 24 * time.Hour,
		"1.5d": 36 * time.Hour,
		"12h":  12 * time.Hour,
	}
	for in, want := range tests {
		if got, err := parseDays(in); err != nil || got != want {
			t.Errorf("parseDays(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"d", "xd", "-1d", "-2h", "week"} {
		if _, err := parseDays(in); err == nil {
			t.Errorf("parseDays(%q): want error", in)
		}
	}
}

func TestSystemWebhookNeedsSystemPackages(t *testing.T) {
	if code := run([]string{"-S", "http://127.0.0.1:1", "--skip-system", "--notify-system-url", "http://127.0.0.1:1/hook"}); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
}

func TestCollectFindingsNamesComposerPackagesOnce(t *testing.T) {
	resp := &rozhanitsy.CheckResponse{ByLocation: map[string]*rozhanitsy.LocationReport{
		"/www/composer.lock": {Vulnerable: []rozhanitsy.Vulnerability{
			{Vendor: "squizlabs", Product: "squizlabs/php_codesniffer", InstalledVersion: "2.9.2", CVEID: "GHSA-hmqg-cxww-wqhq"},
			{Vendor: "haxx", Product: "curl", InstalledVersion: "8.0", CVEID: "CVE-1"},
		}},
	}}
	var got []string
	for _, f := range collectFindings(resp, nil) {
		got = append(got, f.Component)
	}
	sort.Strings(got)
	if want := "haxx/curl,squizlabs/php_codesniffer"; strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

func TestDropForeignRPMsKeepsOnlyDistroBuildFindings(t *testing.T) {
	const nginx = "1.31.8-.el10" // self-built, epoch 0, ahead of every Rocky nginx
	fixedIn := []string{
		"2:1.26.3-2.el10_1.2", "2:1.26.3-6.el10_2.3", "2:1.26.3-6.el10_2.4", "2:1.26.3-16.el10_3.1",
	}
	advisories := []string{"RLSA-2026:4705", "RLSA-2026:6906", "RLSA-2026:18063", "RLSA-2026:19159", "RLSA-2026:29874"}

	resp := &rozhanitsy.CheckResponse{ByLocation: map[string]*rozhanitsy.LocationReport{"rpm": {}}}
	for i, id := range advisories {
		v := rozhanitsy.Vulnerability{
			Product: "nginx", InstalledVersion: nginx, LocalID: "rpm",
			CVEID: id, CVSSSeverity: "HIGH", FixedIn: fixedIn[i%len(fixedIn)],
		}
		resp.Vulnerable = append(resp.Vulnerable, v)
		resp.ByLocation["rpm"].Vulnerable = append(resp.ByLocation["rpm"].Vulnerable, v)
	}
	// A distro build that really is behind its erratum stays a finding.
	kept := rozhanitsy.Vulnerability{
		Product: "openssl", InstalledVersion: "1:3.5.1-4.el10_2", LocalID: "rpm",
		CVEID: "RLSA-2026:70000", CVSSSeverity: "CRITICAL", FixedIn: "1:3.5.1-9.el10_3",
	}
	resp.Vulnerable = append(resp.Vulnerable, kept)
	resp.ByLocation["rpm"].Vulnerable = append(resp.ByLocation["rpm"].Vulnerable, kept)

	if moved := dropForeignRPMs(resp); moved != len(advisories) {
		t.Fatalf("moved %d findings, want %d", moved, len(advisories))
	}
	if len(resp.Vulnerable) != 1 || resp.Vulnerable[0].CVEID != kept.CVEID {
		t.Errorf("findings left: %+v, want only %s", resp.Vulnerable, kept.CVEID)
	}
	if len(resp.Unmatched) != 1 || resp.Unmatched[0].Product != "nginx" || resp.Unmatched[0].Note != foreignRPMNote {
		t.Errorf("unmatched: %+v, want one noted nginx entry", resp.Unmatched)
	}
	if got := resp.ByLocation["rpm"]; len(got.Vulnerable) != 1 || len(got.Unmatched) != 1 {
		t.Errorf("location report: %+v", got)
	}
}
