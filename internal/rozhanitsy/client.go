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

// CheckRequest is the body of a POST /api/vulns/check request.
type CheckRequest struct {
	TenantID   string      `json:"tenant_id,omitempty"`
	Components []Component `json:"components"`
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
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	LocalID string `json:"local_id"`
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

// CheckVulns submits components (and an optional tenant ID) for a vulnerability
// check. Requests are split into batches of at most 2000 components, per the
// API's validation limit, and results are merged.
func (c *Client) CheckVulns(ctx context.Context, tenantID string, components []Component) (*CheckResponse, error) {
	if len(components) == 0 {
		return &CheckResponse{TenantID: tenantID, CheckedAt: time.Now()}, nil
	}

	merged := &CheckResponse{TenantID: tenantID}
	for start := 0; start < len(components); start += maxComponentsPerRequest {
		end := min(start+maxComponentsPerRequest, len(components))

		batch, err := c.checkVulnsBatch(ctx, tenantID, components[start:end])
		if err != nil {
			return nil, err
		}

		merged.Vulnerable = append(merged.Vulnerable, batch.Vulnerable...)
		merged.Unmatched = append(merged.Unmatched, batch.Unmatched...)
		merged.CheckedAt = batch.CheckedAt
	}

	return merged, nil
}

func (c *Client) checkVulnsBatch(ctx context.Context, tenantID string, components []Component) (*CheckResponse, error) {
	reqBody, err := json.Marshal(CheckRequest{TenantID: tenantID, Components: components})
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
