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
				v := apiVulnerability{ID: "CVE-1", CVSSScore: 6, Severity: "MEDIUM", Confidence: "high"}
				v.AffectedRange.PlugsInto = "wordpress"
				res.Vulnerabilities = []apiVulnerability{v}
			case "other":
				res.Vulnerabilities = []apiVulnerability{{ID: "CVE-2", CVSSScore: 9, Severity: "CRITICAL", Confidence: "high"}, {ID: "CVE-3", Confidence: "low"}}
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
