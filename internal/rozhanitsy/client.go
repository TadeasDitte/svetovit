package rozhanitsy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxComponentsPerRequest is the batch endpoint's limit.
const maxComponentsPerRequest = 100

// maxRetries is how many times a rate-limited (429) request is retried.
const maxRetries = 5

const keySep = "\x1f"

type Component struct {
	Vendor    string `json:"vendor,omitempty"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty"`
	LocalID   string `json:"local_id,omitempty"`

	// NVDOnly ignores OSV advisories for this component. OSV records are scoped to a distro or ecosystem
	// whose version ranges mean nothing for a component that has no ecosystem to compare against.
	NVDOnly bool `json:"-"`
}

// requestKey identifies a component to send; identical components found at several locations are
// sent once and mapped back to every location.
func requestKey(comp Component) string {
	return strings.Join([]string{comp.Vendor, comp.Product, comp.Version, comp.Ecosystem}, keySep)
}

type batchPackage struct {
	Vendor    string `json:"vendor,omitempty"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type batchRequest struct {
	Packages             []batchPackage `json:"packages"`
	IncludeLowConfidence bool           `json:"include_low_confidence"`
}

type apiVulnerability struct {
	ID         string  `json:"id"`
	Source     string  `json:"source"`
	CVSSScore  float64 `json:"cvss_score"`
	Severity   string  `json:"severity"`
	Confidence string  `json:"confidence"`
	FixedIn    string  `json:"fixed_in"`

	AffectedRange struct {
		Vendor string `json:"vendor"`
	} `json:"affected_range"`
}

type checkResult struct {
	Vendor          string             `json:"vendor"`
	Product         string             `json:"product"`
	Version         string             `json:"version"`
	Ambiguous       bool               `json:"ambiguous"`
	Vulnerabilities []apiVulnerability `json:"vulnerabilities"`
}

type batchResponse struct {
	Data []checkResult `json:"data"`
}

type Vulnerability struct {
	Vendor           string  `json:"vendor"`
	Product          string  `json:"product"`
	LocalID          string  `json:"local_id,omitempty"`
	InstalledVersion string  `json:"installed_version"`
	CVEID            string  `json:"cve_id"`
	CVSSScore        float64 `json:"cvss_score"`
	CVSSSeverity     string  `json:"cvss_severity"`
	FixedIn          string  `json:"fixed_in,omitempty"`
}

// UnmatchedComponent is a component whose only matches are low-confidence: the source named the
// product but gave no version bounds.
type UnmatchedComponent struct {
	Vendor           string `json:"vendor"`
	Product          string `json:"product"`
	InstalledVersion string `json:"installed_version"`
	LocalID          string `json:"local_id,omitempty"`

	// Ambiguous marks a product name shared by several vendors or ecosystems; the API refuses to
	// guess and returns nothing until the request names a vendor or ecosystem.
	Ambiguous bool `json:"ambiguous,omitempty"`
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
	case http.StatusUnprocessableEntity:
		return fmt.Sprintf("rozhanitsy: validation failed: %s", e.Body)
	case http.StatusTooManyRequests:
		return "rozhanitsy: rate limit exceeded (60 requests/minute)"
	default:
		return fmt.Sprintf("rozhanitsy: unexpected status %d: %s", e.StatusCode, e.Body)
	}
}

type Client struct {
	BaseURL string
	// Token is optional: the API is public, but a bearer token is sent when one is set.
	Token string
	HTTP  *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// CheckVulns checks components against the vulnerability database. includeLow also returns
// low-confidence matches, which are reported as Unmatched. minScore and severities filter results
// client-side.
func (c *Client) CheckVulns(ctx context.Context, components []Component, minScore float64, severities []string, includeLow bool) (*CheckResponse, error) {
	merged := &CheckResponse{CheckedAt: time.Now(), ByLocation: make(map[string]*LocationReport)}
	if len(components) == 0 {
		return merged, nil
	}

	allowed := make(map[string]bool, len(severities))
	for _, s := range severities {
		allowed[strings.ToUpper(strings.TrimSpace(s))] = true
	}

	// Dedupe, keeping first-seen order so batches are deterministic.
	var keys []string
	unique := make(map[string]Component)
	locations := make(map[string][]string)
	for _, comp := range components {
		key := requestKey(comp)
		if _, seen := unique[key]; !seen {
			unique[key] = comp
			keys = append(keys, key)
		}
		locations[key] = append(locations[key], comp.LocalID)
	}

	for start := 0; start < len(keys); start += maxComponentsPerRequest {
		end := min(start+maxComponentsPerRequest, len(keys))
		batchKeys := keys[start:end]

		packages := make([]batchPackage, len(batchKeys))
		for i, key := range batchKeys {
			comp := unique[key]
			packages[i] = batchPackage{Vendor: comp.Vendor, Product: comp.Product, Version: comp.Version, Ecosystem: comp.Ecosystem}
		}

		results, err := c.checkBatch(ctx, packages, includeLow)
		if err != nil {
			return nil, err
		}
		if len(results) != len(batchKeys) {
			return nil, fmt.Errorf("rozhanitsy: got %d results for %d packages", len(results), len(batchKeys))
		}

		for i, key := range batchKeys {
			comp := unique[key]
			locs := locations[key]
			localID := strings.Join(locs, ",")

			hasHigh, hasLow := false, results[i].Ambiguous
			for _, v := range results[i].Vulnerabilities {
				if comp.NVDOnly && v.Source != "nvd" {
					continue
				}
				if v.Confidence == "low" {
					hasLow = true
					continue
				}
				hasHigh = true
				if v.CVSSScore < minScore || (len(allowed) > 0 && !allowed[strings.ToUpper(v.Severity)]) {
					continue
				}
				vendor := comp.Vendor
				if vendor == "" {
					vendor = v.AffectedRange.Vendor
				}
				vuln := Vulnerability{
					Vendor:           vendor,
					Product:          comp.Product,
					LocalID:          localID,
					InstalledVersion: comp.Version,
					CVEID:            v.ID,
					CVSSScore:        v.CVSSScore,
					CVSSSeverity:     strings.ToUpper(v.Severity),
					FixedIn:          v.FixedIn,
				}
				merged.Vulnerable = append(merged.Vulnerable, vuln)
				for _, loc := range locs {
					entry := merged.locationEntry(loc)
					entry.Vulnerable = append(entry.Vulnerable, vuln)
				}
			}

			if hasLow && !hasHigh {
				unm := UnmatchedComponent{Vendor: comp.Vendor, Product: comp.Product, InstalledVersion: comp.Version, LocalID: localID, Ambiguous: results[i].Ambiguous}
				merged.Unmatched = append(merged.Unmatched, unm)
				for _, loc := range locs {
					entry := merged.locationEntry(loc)
					entry.Unmatched = append(entry.Unmatched, unm)
				}
			}
		}
		merged.CheckedAt = time.Now()
	}

	return merged, nil
}

// checkBatch posts one batch.
func (c *Client) checkBatch(ctx context.Context, packages []batchPackage, includeLow bool) ([]checkResult, error) {
	reqBody, err := json.Marshal(batchRequest{Packages: packages, IncludeLowConfidence: includeLow})
	if err != nil {
		return nil, fmt.Errorf("rozhanitsy: encoding request: %w", err)
	}
	var result batchResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/check/batch", reqBody, &result); err != nil {
		return nil, err
	}
	return result.Data, nil
}

// do sends one API request and decodes the JSON reply into out, retrying while the server
// rate-limits (429).
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	for attempt := 0; ; attempt++ {
		retryAfter, err := c.doOnce(ctx, method, path, body, out)
		if err == nil {
			return nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusTooManyRequests || attempt >= maxRetries {
			return err
		}
		select {
		case <-time.After(retryAfter):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *Client) doOnce(ctx context.Context, method, path string, body []byte, out any) (time.Duration, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return 0, fmt.Errorf("rozhanitsy: building request: %w", err)
	}
	if c.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return 0, fmt.Errorf("rozhanitsy: request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("rozhanitsy: reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return retryDelay(resp), &APIError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return 0, fmt.Errorf("rozhanitsy: decoding response: %w", err)
	}
	return 0, nil
}

// retryDelay honors Retry-After (seconds) and otherwise waits a second, the rate limit being per minute.
func retryDelay(resp *http.Response) time.Duration {
	if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return time.Second
}
