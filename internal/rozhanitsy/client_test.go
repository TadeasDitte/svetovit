package rozhanitsy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckVulnsBatchesRetriesAndMapsLocations(t *testing.T) {
	var requests, limited atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/check/batch" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if limited.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		requests.Add(1)
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if len(req.Packages) > maxComponentsPerRequest {
			t.Errorf("batch of %d exceeds limit", len(req.Packages))
		}
		out := batchResponse{}
		for _, p := range req.Packages {
			res := checkResult{Product: p.Product, Version: p.Version}
			switch p.Product {
			case "vuln":
				res.Vulnerabilities = []apiVulnerability{{ID: "CVE-1", CVSSScore: new(9.8), Severity: "CRITICAL", Confidence: "high"}}
			case "maybe":
				res.Vulnerabilities = []apiVulnerability{{ID: "CVE-2", CVSSScore: new(5.0), Severity: "MEDIUM", Confidence: "low"}}
			}
			out.Data = append(out.Data, res)
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	components := []Component{
		{Product: "vuln", Version: "1", LocalID: "/a"},
		{Product: "vuln", Version: "1", LocalID: "/b"}, // duplicate, second location
		{Product: "maybe", Version: "1", LocalID: "/a"},
	}
	for i := 0; i < 230; i++ {
		components = append(components, Component{Product: fmt.Sprintf("p%d", i), Version: "1", LocalID: "/c"})
	}

	resp, err := New(srv.URL, "").CheckVulns(context.Background(), components, 0, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 3 { // 232 unique components -> 3 batches
		t.Errorf("want 3 successful requests, got %d", got)
	}
	if len(resp.Vulnerable) != 1 || resp.Vulnerable[0].LocalID != "/a,/b" {
		t.Errorf("unexpected vulnerable: %+v", resp.Vulnerable)
	}
	if len(resp.ByLocation["/a"].Vulnerable) != 1 || len(resp.ByLocation["/b"].Vulnerable) != 1 {
		t.Errorf("duplicate component not mapped to both locations: %+v", resp.ByLocation)
	}
	if len(resp.Unmatched) != 1 || resp.Unmatched[0].Product != "maybe" {
		t.Errorf("unexpected unmatched: %+v", resp.Unmatched)
	}
}

func TestCheckVulnsFiltersByScoreAndSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(batchResponse{Data: []checkResult{{Vulnerabilities: []apiVulnerability{
			{ID: "CVE-LOW", CVSSScore: new(3.0), Severity: "LOW", Confidence: "high"},
			{ID: "CVE-HIGH", CVSSScore: new(8.0), Severity: "HIGH", Confidence: "high"},
		}}}})
	}))
	defer srv.Close()

	resp, err := New(srv.URL, "").CheckVulns(context.Background(), []Component{{Product: "x", Version: "1"}}, 5, []string{"high"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Vulnerable) != 1 || resp.Vulnerable[0].CVEID != "CVE-HIGH" {
		t.Errorf("unexpected vulnerable: %+v", resp.Vulnerable)
	}
}

func TestNVDOnlyDropsOSVAdvisories(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(batchResponse{Data: []checkResult{{Vulnerabilities: []apiVulnerability{
			{ID: "DEBIAN-CVE-1", Source: "osv", CVSSScore: new(9.0), Severity: "Critical", Confidence: "high"},
			{ID: "CVE-1", Source: "nvd", CVSSScore: new(9.0), Severity: "Critical", Confidence: "high"},
		}}}})
	}))
	defer srv.Close()

	resp, err := New(srv.URL, "").CheckVulns(context.Background(), []Component{{Product: "x", Version: "1", NVDOnly: true}}, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Vulnerable) != 1 || resp.Vulnerable[0].CVEID != "CVE-1" || resp.Vulnerable[0].CVSSSeverity != "CRITICAL" {
		t.Errorf("unexpected vulnerable: %+v", resp.Vulnerable)
	}
}

func TestCheckVulnsTakesVendorFromAffectedRangeAndFlagsAmbiguous(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[
			{"product":"snappy","vulnerable":true,"ambiguous":false,"vulnerabilities":[
				{"id":"CVE-1","cvss_score":7,"severity":"HIGH","confidence":"high","fixed_in":"1.2","affected_range":{"vendor":"knplabs","product":"snappy"}}]},
			{"product":"orc","vulnerable":null,"ambiguous":true,"candidates":[{"vendor":"apache"},{"vendor":"other"}],"vulnerabilities":[]}]}`)
	}))
	defer srv.Close()

	resp, err := New(srv.URL, "").CheckVulns(context.Background(), []Component{
		{Product: "snappy", Version: "1", LocalID: "/a"},
		{Product: "orc", Version: "1", LocalID: "/a"},
	}, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Vulnerable) != 1 || resp.Vulnerable[0].Vendor != "knplabs" || resp.Vulnerable[0].FixedIn != "1.2" {
		t.Errorf("unexpected vulnerable: %+v", resp.Vulnerable)
	}
	if len(resp.Unmatched) != 1 || resp.Unmatched[0].Product != "orc" || !resp.Unmatched[0].Ambiguous {
		t.Errorf("ambiguous product not reported as unmatched: %+v", resp.Unmatched)
	}
}

func TestRemoveAndMerge(t *testing.T) {
	a := Vulnerability{Product: "orc", CVEID: "CVE-A", LocalID: "/s"}
	b := Vulnerability{Product: "zlib", CVEID: "CVE-B", LocalID: "/s"}
	resp := &CheckResponse{Vulnerable: []Vulnerability{a, b}, ByLocation: map[string]*LocationReport{"/s": {Vulnerable: []Vulnerability{a, b}}}}

	resp.Remove(func(p string) bool { return p == "orc" })
	resp.Merge(&CheckResponse{Vulnerable: []Vulnerability{{Product: "orc", Vendor: "gstreamer", CVEID: "CVE-C", LocalID: "/s"}},
		ByLocation: map[string]*LocationReport{"/s": {Vulnerable: []Vulnerability{{Product: "orc", Vendor: "gstreamer", CVEID: "CVE-C"}}}}})

	if len(resp.Vulnerable) != 2 || resp.Vulnerable[0].CVEID != "CVE-B" || resp.Vulnerable[1].CVEID != "CVE-C" {
		t.Errorf("unexpected vulnerable: %+v", resp.Vulnerable)
	}
	if got := resp.ByLocation["/s"].Vulnerable; len(got) != 2 || got[0].CVEID != "CVE-B" || got[1].CVEID != "CVE-C" {
		t.Errorf("unexpected by-location: %+v", got)
	}
}

func TestCheckVulnsResolvesAmbiguousCandidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		json.NewDecoder(r.Body).Decode(&req)
		out := batchResponse{}
		for _, p := range req.Packages {
			res := checkResult{Product: p.Product}
			switch p.Vendor {
			case "":
				res.Ambiguous = true
				res.Candidates = []candidate{{Vendor: "automattic"}, {Vendor: "other"}}
			case "automattic":
				v := apiVulnerability{ID: "CVE-1", CVSSScore: new(6.0), Severity: "MEDIUM", Confidence: "high"}
				v.AffectedRange.PlugsInto = "wordpress"
				res.Vulnerabilities = []apiVulnerability{v}
			case "other":
				res.Vulnerabilities = []apiVulnerability{{ID: "CVE-2", CVSSScore: new(9.0), Severity: "CRITICAL", Confidence: "high"}, {ID: "CVE-3", Confidence: "low"}}
			}
			out.Data = append(out.Data, res)
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	comps := []Component{
		{Product: "akismet", Version: "3", LocalID: "/a", ResolveAmbiguous: true, Platform: "wordpress"},
		{Product: "akismet", Version: "3", LocalID: "/b", ResolveAmbiguous: true, Platform: "wordpress"},
		{Product: "orc", Version: "1", LocalID: "/s"},
	}
	resp, err := New(srv.URL, "").CheckVulns(context.Background(), comps, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Vulnerable) != 1 || resp.Vulnerable[0].Vendor != "automattic" || resp.Vulnerable[0].LocalID != "/a,/b" {
		t.Errorf("unexpected vulnerable: %+v", resp.Vulnerable)
	}
	if len(resp.Unmatched) != 1 || resp.Unmatched[0].Product != "orc" {
		t.Errorf("only the non-resolvable component should stay unmatched: %+v", resp.Unmatched)
	}
}

func TestRetriesServerErrorsButNotClientErrors(t *testing.T) {
	var calls atomic.Int32
	status := http.StatusInternalServerError
	failures := int32(2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= failures {
			w.WriteHeader(status)
			return
		}
		json.NewEncoder(w).Encode(batchResponse{Data: []checkResult{{}}})
	}))
	defer srv.Close()

	client := New(srv.URL, "")
	client.RetryBackoff = time.Millisecond
	comps := []Component{{Product: "x", Version: "1"}}

	if _, err := client.CheckVulns(context.Background(), comps, 0, nil, false); err != nil {
		t.Fatalf("two 500s then success should succeed: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("want 3 calls, got %d", calls.Load())
	}

	calls.Store(0)
	failures = 1000
	if _, err := client.CheckVulns(context.Background(), comps, 0, nil, false); err == nil {
		t.Error("persistent 500 should fail")
	}
	if calls.Load() != maxRetries+1 {
		t.Errorf("want %d calls for a persistent 500, got %d", maxRetries+1, calls.Load())
	}

	calls.Store(0)
	status = http.StatusUnprocessableEntity
	if _, err := client.CheckVulns(context.Background(), comps, 0, nil, false); err == nil {
		t.Error("422 should fail")
	}
	if calls.Load() != 1 {
		t.Errorf("422 must not be retried, got %d calls", calls.Load())
	}
}

func TestQualifiedName(t *testing.T) {
	tests := []struct{ vendor, product, want string }{
		{"", "curl", "curl"},
		{"haxx", "curl", "haxx/curl"},
		{"same", "same", "same"},
		{"squizlabs", "squizlabs/php_codesniffer", "squizlabs/php_codesniffer"},
		{"@babel", "@babel/core", "@babel/core"},
		{"acme", "acme-tools", "acme/acme-tools"},
	}
	for _, tt := range tests {
		if got := QualifiedName(tt.vendor, tt.product); got != tt.want {
			t.Errorf("QualifiedName(%q, %q) = %q, want %q", tt.vendor, tt.product, got, tt.want)
		}
	}
}

func TestMeetsMinScore(t *testing.T) {
	tests := []struct {
		name     string
		score    *float64
		severity string
		min      float64
		want     bool
	}{
		{"no threshold", nil, "LOW", 0, true},
		{"known above", new(7.5), "HIGH", 7, true},
		{"known below", new(6.9), "MEDIUM", 7, false},
		{"known score beats severity", new(3.0), "CRITICAL", 7, false},
		{"unknown critical", nil, "CRITICAL", 7, true},
		{"unknown high at 7", nil, "HIGH", 7, true},
		{"unknown high, case-insensitive", nil, "high", 7, true},
		{"unknown medium", nil, "MEDIUM", 7, false},
		{"unknown low", nil, "LOW", 4, false},
		{"unknown high above its band floor", nil, "HIGH", 8, false},
		{"unknown critical at 9", nil, "CRITICAL", 9, true},
		{"nothing to judge by is kept", nil, "", 9, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MeetsMinScore(tt.score, tt.severity, tt.min); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckVulnsKeepsUnknownScoresForMinScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[{"product":"pkg","version":"1","vulnerabilities":[
			{"id":"GHSA-high","cvss_score":null,"severity":"HIGH","confidence":"high"},
			{"id":"GHSA-crit","cvss_score":null,"severity":"CRITICAL","confidence":"high"},
			{"id":"GHSA-med","cvss_score":null,"severity":"MEDIUM","confidence":"high"},
			{"id":"CVE-scored","cvss_score":7.8,"severity":"HIGH","confidence":"high"},
			{"id":"CVE-low","cvss_score":2.1,"severity":"LOW","confidence":"high"}]}]}`)
	}))
	defer srv.Close()

	resp, err := New(srv.URL, "").CheckVulns(context.Background(), []Component{{Product: "pkg", Version: "1", LocalID: "/a"}}, 7, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*float64{}
	for _, v := range resp.Vulnerable {
		got[v.CVEID] = v.CVSSScore
	}
	if len(got) != 3 || got["GHSA-high"] != nil || got["GHSA-crit"] != nil || got["CVE-scored"] == nil || *got["CVE-scored"] != 7.8 {
		t.Errorf("unexpected vulnerable set: %+v", got)
	}
}
