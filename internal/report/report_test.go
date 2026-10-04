package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TadeasDitte/Svetovit/internal/rozhanitsy"
)

var checkedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func sampleVulns() []rozhanitsy.Vulnerability {
	return []rozhanitsy.Vulnerability{
		{Product: "low", CVEID: "CVE-LOW", CVSSScore: 2.0, CVSSSeverity: "LOW", InstalledVersion: "1"},
		{Vendor: "acme", Product: "crit", CVEID: "CVE-CRIT", CVSSScore: 9.8, CVSSSeverity: "CRITICAL", InstalledVersion: "2", LocalID: "/a"},
		{Product: "high-b", CVEID: "CVE-HB", CVSSScore: 7.5, CVSSSeverity: "HIGH", InstalledVersion: "3"},
		{Vendor: "same", Product: "same", CVEID: "CVE-HA", CVSSScore: 8.1, CVSSSeverity: "HIGH", InstalledVersion: "4"},
	}
}

func TestFilterApply(t *testing.T) {
	vulns := sampleVulns()
	cves := func(vs []rozhanitsy.Vulnerability) string {
		var ids []string
		for _, v := range vs {
			ids = append(ids, v.CVEID)
		}
		return strings.Join(ids, ",")
	}

	tests := []struct {
		name   string
		filter Filter
		want   string
	}{
		{"zero filter keeps all", Filter{}, "CVE-LOW,CVE-CRIT,CVE-HB,CVE-HA"},
		{"min score", Filter{MinScore: 8}, "CVE-CRIT,CVE-HA"},
		{"severity", Filter{Severities: []string{"high"}}, "CVE-HB,CVE-HA"},
		{"severity trims and ignores case", Filter{Severities: []string{" Critical ", "low"}}, "CVE-LOW,CVE-CRIT"},
		{"score and severity combine", Filter{MinScore: 8, Severities: []string{"HIGH"}}, "CVE-HA"},
		{"nothing matches", Filter{MinScore: 10}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cves(tt.filter.Apply(vulns)); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPrintSortsBySeverityThenScore(t *testing.T) {
	var buf bytes.Buffer
	Print(&buf, &rozhanitsy.CheckResponse{CheckedAt: checkedAt, Vulnerable: sampleVulns()}, nil, Sections{Bounded: true}, false)
	out := buf.String()

	if !strings.HasPrefix(out, "Scan checked at 2026-01-02T03:04:05Z\n") {
		t.Errorf("missing header:\n%s", out)
	}
	if !strings.Contains(out, "4 known vulnerabilities found:") {
		t.Errorf("missing count:\n%s", out)
	}
	last := -1
	for _, id := range []string{"CVE-CRIT", "CVE-HA", "CVE-HB", "CVE-LOW"} {
		i := strings.Index(out, id)
		if i < 0 || i < last {
			t.Fatalf("%s out of order or missing:\n%s", id, out)
		}
		last = i
	}
	if !strings.Contains(out, "acme/crit") {
		t.Errorf("vendor should prefix product:\n%s", out)
	}
	if strings.Contains(out, "same/same") {
		t.Errorf("vendor equal to product should not be repeated:\n%s", out)
	}
	if !strings.Contains(out, "LOCATION(S)") {
		t.Errorf("flat view should have a location column:\n%s", out)
	}
}

func TestPrintDoesNotMutateInput(t *testing.T) {
	vulns := sampleVulns()
	Print(&bytes.Buffer{}, &rozhanitsy.CheckResponse{CheckedAt: checkedAt, Vulnerable: vulns}, nil, Sections{Bounded: true}, false)
	if vulns[0].CVEID != "CVE-LOW" {
		t.Error("Print reordered the caller's slice")
	}
}

func TestPrintSingularAndEmpty(t *testing.T) {
	var buf bytes.Buffer
	resp := &rozhanitsy.CheckResponse{
		CheckedAt:  checkedAt,
		Vulnerable: sampleVulns()[:1],
		Unmatched:  []rozhanitsy.UnmatchedComponent{{Vendor: "v", Product: "p", LocalID: "/x", Ambiguous: true}},
	}
	Print(&buf, resp, nil, Sections{Bounded: true, Unbound: true}, false)
	out := buf.String()
	for _, want := range []string{
		"1 known vulnerability found:",
		"1 component could not be matched",
		"- v/p (/x) [ambiguous name, several vendors]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	buf.Reset()
	Print(&buf, &rozhanitsy.CheckResponse{CheckedAt: checkedAt}, nil, Sections{Bounded: true, Unbound: true}, false)
	out = buf.String()
	for _, want := range []string{"No known vulnerabilities found", "No unmatched components."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestPrintHonoursSections(t *testing.T) {
	resp := &rozhanitsy.CheckResponse{
		CheckedAt:  checkedAt,
		Vulnerable: sampleVulns()[:1],
		Unmatched:  []rozhanitsy.UnmatchedComponent{{Product: "p"}},
	}
	var buf bytes.Buffer
	Print(&buf, resp, nil, Sections{Bounded: true}, false)
	if strings.Contains(buf.String(), "could not be matched") {
		t.Errorf("unbound section should be hidden:\n%s", buf.String())
	}
	buf.Reset()
	Print(&buf, resp, nil, Sections{Unbound: true}, false)
	if strings.Contains(buf.String(), "known vulnerab") {
		t.Errorf("bounded section should be hidden:\n%s", buf.String())
	}
}

func TestPrintByLocation(t *testing.T) {
	resp := &rozhanitsy.CheckResponse{
		CheckedAt: checkedAt,
		ByLocation: map[string]*rozhanitsy.LocationReport{
			"/z": {Unmatched: []rozhanitsy.UnmatchedComponent{{Product: "zp", LocalID: "/z"}}},
			"/a": {Vulnerable: sampleVulns()[:1]},
		},
	}
	var buf bytes.Buffer
	Print(&buf, resp, nil, Sections{Bounded: true, Unbound: true}, true)
	out := buf.String()
	if a, z := strings.Index(out, "Location: /a"), strings.Index(out, "Location: /z"); a < 0 || z < 0 || a > z {
		t.Errorf("locations missing or unsorted:\n%s", out)
	}
	if strings.Contains(out, "LOCATION(S)") {
		t.Errorf("per-location view should omit the location column:\n%s", out)
	}

	buf.Reset()
	Print(&buf, &rozhanitsy.CheckResponse{CheckedAt: checkedAt}, nil, Sections{Bounded: true}, true)
	if !strings.Contains(buf.String(), "No locations to report") {
		t.Errorf("got:\n%s", buf.String())
	}
}

func TestPrintSystemBlock(t *testing.T) {
	sys := &System{
		Name:      "Debian 12",
		Ecosystem: "Debian:12",
		Response: &rozhanitsy.CheckResponse{
			Vulnerable: sampleVulns()[:1],
			Unmatched:  []rozhanitsy.UnmatchedComponent{{Product: "a"}, {Product: "b"}},
		},
	}
	var buf bytes.Buffer
	Print(&buf, &rozhanitsy.CheckResponse{CheckedAt: checkedAt}, sys, Sections{Bounded: true, Unbound: true}, false)
	out := buf.String()
	for _, want := range []string{
		"System packages: Debian 12 (Debian:12)",
		"1 known vulnerability found:",
		"2 packages could not be matched",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	// No ecosystem (NixOS): heading is just the name.
	buf.Reset()
	sys.Ecosystem = ""
	Print(&buf, &rozhanitsy.CheckResponse{CheckedAt: checkedAt}, sys, Sections{Bounded: true}, false)
	if !strings.Contains(buf.String(), "System packages: Debian 12\n") {
		t.Errorf("got:\n%s", buf.String())
	}
}

func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, buf.String())
	}
	return out
}

func TestWriteJSONFlat(t *testing.T) {
	resp := &rozhanitsy.CheckResponse{
		CheckedAt:  checkedAt,
		Vulnerable: sampleVulns()[:1],
		ByLocation: map[string]*rozhanitsy.LocationReport{"/a": {}},
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, resp, nil, Sections{Bounded: true, Unbound: true}, false); err != nil {
		t.Fatal(err)
	}
	out := decode(t, &buf)
	if v, ok := out["vulnerable"].([]any); !ok || len(v) != 1 {
		t.Errorf("vulnerable = %v", out["vulnerable"])
	}
	// nil Unmatched must serialise as [] when the section is requested.
	if u, ok := out["unmatched"].([]any); !ok || len(u) != 0 {
		t.Errorf("unmatched = %#v, want []", out["unmatched"])
	}
	if out["by_location"] != nil {
		t.Errorf("by_location should be dropped in flat mode: %v", out["by_location"])
	}
	if _, ok := out["system"]; ok {
		t.Error("system should be omitted when nil")
	}
}

func TestWriteJSONSectionsHideData(t *testing.T) {
	resp := &rozhanitsy.CheckResponse{
		CheckedAt:  checkedAt,
		Vulnerable: sampleVulns()[:1],
		Unmatched:  []rozhanitsy.UnmatchedComponent{{Product: "p"}},
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, resp, nil, Sections{Bounded: true}, false); err != nil {
		t.Fatal(err)
	}
	out := decode(t, &buf)
	if out["unmatched"] != nil {
		t.Errorf("unmatched should be null: %v", out["unmatched"])
	}
	if len(resp.Unmatched) != 1 {
		t.Error("WriteJSON mutated its input")
	}
}

func TestWriteJSONByLocationAndSystem(t *testing.T) {
	resp := &rozhanitsy.CheckResponse{
		CheckedAt:  checkedAt,
		Vulnerable: sampleVulns()[:1],
		ByLocation: map[string]*rozhanitsy.LocationReport{
			"/a": {Vulnerable: sampleVulns()[:1], Unmatched: []rozhanitsy.UnmatchedComponent{{Product: "p"}}},
		},
	}
	sys := &System{Name: "Alpine", Ecosystem: "Alpine:v3.19", Response: &rozhanitsy.CheckResponse{
		Unmatched: []rozhanitsy.UnmatchedComponent{{Product: "musl"}},
	}}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, resp, sys, Sections{Bounded: true}, true); err != nil {
		t.Fatal(err)
	}
	out := decode(t, &buf)

	loc := out["by_location"].(map[string]any)["/a"].(map[string]any)
	if loc["vulnerable"] == nil || loc["unmatched"] != nil {
		t.Errorf("location sections not filtered: %v", loc)
	}
	if out["vulnerable"] != nil {
		t.Errorf("top-level vulnerable should be null in by-location mode: %v", out["vulnerable"])
	}
	s := out["system"].(map[string]any)
	if s["name"] != "Alpine" || s["ecosystem"] != "Alpine:v3.19" {
		t.Errorf("system = %v", s)
	}
	if s["unmatched"] != nil {
		t.Errorf("system unmatched should be hidden without the unbound section: %v", s["unmatched"])
	}
	if s["by_location"] != nil {
		t.Errorf("system is never reported by location: %v", s["by_location"])
	}
}
