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
