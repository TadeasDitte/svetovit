package rozhanitsy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
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
				res.Vulnerabilities = []apiVulnerability{{ID: "CVE-1", CVSSScore: 9.8, Severity: "CRITICAL", Confidence: "high"}}
			case "maybe":
				res.Vulnerabilities = []apiVulnerability{{ID: "CVE-2", CVSSScore: 5, Severity: "MEDIUM", Confidence: "low"}}
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
			{ID: "CVE-LOW", CVSSScore: 3, Severity: "LOW", Confidence: "high"},
			{ID: "CVE-HIGH", CVSSScore: 8, Severity: "HIGH", Confidence: "high"},
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
			{ID: "DEBIAN-CVE-1", Source: "osv", CVSSScore: 9, Severity: "Critical", Confidence: "high"},
			{ID: "CVE-1", Source: "nvd", CVSSScore: 9, Severity: "Critical", Confidence: "high"},
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

func TestAnnotateVendorsUsesDetailsEndpointOnce(t *testing.T) {
	var lookups atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/vulnerabilities/CVE-1":
			lookups.Add(1)
			fmt.Fprint(w, `{"data":[{"affected":[{"vendor":"knplabs","product":"snappy"},{"vendor":"other","product":"unrelated"}]}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	vuln := Vulnerability{Product: "snappy", CVEID: "CVE-1", LocalID: "/a"}
	resp := &CheckResponse{
		Vulnerable: []Vulnerability{vuln, {Product: "snappy", CVEID: "CVE-1", LocalID: "/b"}, {Product: "x", CVEID: "CVE-GONE"}},
		ByLocation: map[string]*LocationReport{"/a": {Vulnerable: []Vulnerability{vuln}}},
	}
	skipped, err := New(srv.URL, "").AnnotateVendors(context.Background(), resp)
	if err != nil || skipped != 0 {
		t.Fatalf("skipped=%d err=%v", skipped, err)
	}
	if resp.Vulnerable[0].Vendor != "knplabs" || resp.Vulnerable[1].Vendor != "knplabs" || resp.ByLocation["/a"].Vulnerable[0].Vendor != "knplabs" {
		t.Errorf("vendor not annotated: %+v", resp)
	}
	if resp.Vulnerable[2].Vendor != "" {
		t.Errorf("unknown CVE should stay blank: %+v", resp.Vulnerable[2])
	}
	if lookups.Load() != 1 {
		t.Errorf("want 1 details lookup for CVE-1, got %d", lookups.Load())
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
