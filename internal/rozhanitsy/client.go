// Package rozhanitsy is a client for the Rozhanitsy vulnerability intelligence
// API (https://github.com/TadeasDitte/Rozhanitsy/wiki/API).
package rozhanitsy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
)

// maxComponentsPerRequest mirrors the API's validation rule: components is
// required, 1-2000 entries.
const maxComponentsPerRequest = 2000

// Component is a single vendor/product/version to check for known vulnerabilities.
type Component struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
	LocalID string `json:"local_id,omitempty"`
}

func (c Component) toGenericString() string {
	clean := c
	clean.LocalID = ""
	b, err := json.Marshal(clean)
	if err != nil {
		return ""
	}
	return string(b)
}

func (Component) fromString(str string) (Component, error) {
	c := Component{}
	err := json.Unmarshal([]byte(str), &c)
	if err != nil {
		return c, err
	}
	return c, nil
}

// CheckRequest is the body of a POST /api/vulns/check request.
type CheckRequest struct {
	TenantID   string      `json:"tenant_id,omitempty"`
	Components []Component `json:"components"`
	MinScore   float64     `json:"min_cvss_score"`
	Severities []string    `json:"severity,omitempty"`
	// Confidence tells the server which results to compute: "bound"
	// (known-vulnerable), "unbound" (unmatched), or "all".
	Confidence string `json:"confidence"`
}

// Vulnerability is a single known CVE affecting an installed component.
type Vulnerability struct {
	Vendor           string  `json:"vendor"`
	Product          string  `json:"product"`
	LocalID          string  `json:"local_id"`
	InstalledVersion string  `json:"installed_version"`
	CVEID            string  `json:"cve_id"`
	CVSSScore        float64 `json:"cvss_score"`
	CVSSVector       string  `json:"cvss_vector"`
	CVSSSeverity     string  `json:"cvss_severity"`
}

// UnmatchedComponent is a submitted component that could not be resolved
// against the vulnerability database's product catalog.
type UnmatchedComponent struct {
	Vendor           string `json:"vendor"`
	Product          string `json:"product"`
	InstalledVersion string `json:"installed_version"`
	LocalID          string `json:"local_id"`
}

// CheckResponse is the body of a successful POST /api/vulns/check response.
type CheckResponse struct {
	TenantID   string               `json:"tenant_id"`
	Vulnerable []Vulnerability      `json:"vulnerable"`
	Unmatched  []UnmatchedComponent `json:"unmatched"`
	CheckedAt  time.Time            `json:"checked_at"`
}

// APIError is returned for any non-2xx response from the API.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return "rozhanitsy: unauthorized (missing, invalid, revoked token, or deactivated host)"
	case http.StatusUnprocessableEntity:
		return fmt.Sprintf("rozhanitsy: validation failed: %s", e.Body)
	case http.StatusTooManyRequests:
		return "rozhanitsy: rate limit exceeded (30 requests/minute)"
	default:
		return fmt.Sprintf("rozhanitsy: unexpected status %d: %s", e.StatusCode, e.Body)
	}
}

// Client talks to a Rozhanitsy instance's scanner API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New creates a Client for the given Rozhanitsy base URL, authenticating with
// a Sanctum bearer token issued via `scan-host:create` or the web UI.
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// CheckVulns submits components for a vulnerability
// check. Requests are split into batches of at most 2000 components, per the
// API's validation limit, and results are merged. confidence selects which
// results the server computes: "bound", "unbound", or "all".
func (c *Client) CheckVulns(ctx context.Context, components []Component, minScore float64, severities []string, confidence string) (*CheckResponse, error) {
	if len(components) == 0 {
		return &CheckResponse{CheckedAt: time.Now()}, nil
	}

	componentSet := mapset.NewSet[string]()   // deduplicated components by version
	inventoryMap := make(map[string][]string) // site/local_id -> installed components
	affectedMap := make(map[string][]string)  // versioned component -> sites
	for _, c := range components {
		genericId := c.toGenericString()
		componentSet.Add(genericId)
		inventoryMap[c.LocalID] = append(inventoryMap[c.LocalID], genericId)
		affectedMap[genericId] = append(affectedMap[genericId], c.LocalID)
	}

	merged := &CheckResponse{}
	for start := 0; start < componentSet.Cardinality(); start += maxComponentsPerRequest {
		end := min(start+maxComponentsPerRequest, componentSet.Cardinality())
		slice := componentSet.ToSlice()[start:end]

		genericComponents := make([]Component, 0)

		for _, c := range slice {
			component, err := Component.fromString(Component{}, c)
			if err != nil {
				continue
			}
			genericComponents = append(genericComponents, component)
		}

		batch, err := c.checkVulnsBatch(ctx, genericComponents, minScore, severities, confidence)
		if err != nil {
			return nil, err
		}

		newVulns := make([]Vulnerability, 0)
		newUnmatched := make([]UnmatchedComponent, 0)

		for _, vuln := range batch.Vulnerable {
			c := Component{
				Vendor:  vuln.Vendor,
				Product: vuln.Product,
				Version: vuln.InstalledVersion,
			}
			vuln.LocalID = strings.Join(affectedMap[c.toGenericString()], ",")
			newVulns = append(newVulns, vuln)
		}

		for _, unm := range batch.Unmatched {
			c := Component{
				Vendor:  unm.Vendor,
				Product: unm.Product,
				Version: unm.InstalledVersion,
			}
			unm.LocalID = strings.Join(affectedMap[c.toGenericString()], ",")
			newUnmatched = append(newUnmatched, unm)
		}

		merged.Vulnerable = append(merged.Vulnerable, newVulns...)
		merged.Unmatched = append(merged.Unmatched, newUnmatched...)
		merged.CheckedAt = batch.CheckedAt
	}

	return merged, nil
}

func (c *Client) checkVulnsBatch(ctx context.Context, components []Component, minScore float64, severities []string, confidence string) (*CheckResponse, error) {
	reqBody, err := json.Marshal(CheckRequest{Components: components, MinScore: minScore, Severities: severities, Confidence: confidence})
	if err != nil {
		return nil, fmt.Errorf("rozhanitsy: encoding request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/vulns/check", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("rozhanitsy: building request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rozhanitsy: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("rozhanitsy: reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var result CheckResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("rozhanitsy: decoding response: %w", err)
	}

	return &result, nil
}

