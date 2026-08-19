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

const maxComponentsPerRequest = 2000

const keySep = "\x1f"

type Component struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
	LocalID string `json:"local_id,omitempty"`
}

func componentKey(vendor, product, version string) string {
	return vendor + keySep + product + keySep + version
}

func parseComponentKey(key string) (Component, error) {
	parts := strings.Split(key, keySep)
	if len(parts) != 3 {
		return Component{}, fmt.Errorf("rozhanitsy: invalid component key: %q", key)
	}
	return Component{
		Vendor:  parts[0],
		Product: parts[1],
		Version: parts[2],
	}, nil
}

type CheckRequest struct {
	TenantID   string      `json:"tenant_id,omitempty"`
	Components []Component `json:"components"`
	MinScore   float64     `json:"min_cvss_score"`
	Severities []string    `json:"severity,omitempty"`
	Confidence string      `json:"confidence"`
}

type Vulnerability struct {
	Vendor           string  `json:"vendor"`
	Product          string  `json:"product"`
	LocalID          string  `json:"local_id,omitempty"`
	InstalledVersion string  `json:"installed_version"`
	CVEID            string  `json:"cve_id"`
	CVSSScore        float64 `json:"cvss_score"`
	CVSSVector       string  `json:"cvss_vector"`
	CVSSSeverity     string  `json:"cvss_severity"`
}

type UnmatchedComponent struct {
	Vendor           string `json:"vendor"`
	Product          string `json:"product"`
	InstalledVersion string `json:"installed_version"`
	LocalID          string `json:"local_id,omitempty"`
}

type LocationReport struct {
	Vulnerable []Vulnerability      `json:"vulnerable,omitempty"`
	Unmatched  []UnmatchedComponent `json:"unmatched,omitempty"`
}

type CheckResponse struct {
	Vulnerable []Vulnerability            `json:"vulnerable"`
	Unmatched  []UnmatchedComponent       `json:"unmatched"`
	CheckedAt  time.Time                  `json:"checked_at"`
	ByLocation map[string]*LocationReport `json:"by_location"`
}

func (r *CheckResponse) locationEntry(loc string) *LocationReport {
	entry, ok := r.ByLocation[loc]
	if !ok {
		entry = &LocationReport{}
		r.ByLocation[loc] = entry
	}
	return entry
}

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

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) CheckVulns(ctx context.Context, components []Component, minScore float64, severities []string, confidence string) (*CheckResponse, error) {
	if len(components) == 0 {
		return &CheckResponse{CheckedAt: time.Now(), ByLocation: make(map[string]*LocationReport)}, nil
	}

	componentSet := mapset.NewSet[string]()
	affectedMap := make(map[string][]string)
	for _, comp := range components {
		genericID := componentKey(comp.Vendor, comp.Product, comp.Version)
		componentSet.Add(genericID)
		affectedMap[genericID] = append(affectedMap[genericID], comp.LocalID)
	}

	allGeneric := componentSet.ToSlice()
	total := len(allGeneric)

	merged := &CheckResponse{ByLocation: make(map[string]*LocationReport)}

	for start := 0; start < total; start += maxComponentsPerRequest {
		end := min(start+maxComponentsPerRequest, total)
		slice := allGeneric[start:end]

		genericComponents := make([]Component, 0, len(slice))
		for _, s := range slice {
			component, err := parseComponentKey(s)
			if err != nil {
				continue
			}
			genericComponents = append(genericComponents, component)
		}

		batch, err := c.checkVulnsBatch(ctx, genericComponents, minScore, severities, confidence)
		if err != nil {
			return nil, err
		}

		newVulns := make([]Vulnerability, 0, len(batch.Vulnerable))
		newUnmatched := make([]UnmatchedComponent, 0, len(batch.Unmatched))

		for _, vuln := range batch.Vulnerable {
			key := componentKey(vuln.Vendor, vuln.Product, vuln.InstalledVersion)
			locs := affectedMap[key]
			vuln.LocalID = strings.Join(locs, ",")
			newVulns = append(newVulns, vuln)
			for _, loc := range locs {
				entry := merged.locationEntry(loc)
				entry.Vulnerable = append(entry.Vulnerable, vuln)
			}
		}
		for _, unm := range batch.Unmatched {
			key := componentKey(unm.Vendor, unm.Product, unm.InstalledVersion)
			locs := affectedMap[key]
			unm.LocalID = strings.Join(locs, ",")
			newUnmatched = append(newUnmatched, unm)
			for _, loc := range locs {
				entry := merged.locationEntry(loc)
				entry.Unmatched = append(entry.Unmatched, unm)
			}
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
	result.ByLocation = make(map[string]*LocationReport)
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("rozhanitsy: decoding response: %w", err)
	}

	return &result, nil
}
