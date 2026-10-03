package rozhanitsy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// maxVendorLookups bounds the details requests one AnnotateVendors call may make; the API allows
// 60 requests a minute, so each lookup is costly on large result sets.
const maxVendorLookups = 100

type affectedEntry struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

type detailsResponse struct {
	Data []struct {
		Affected []affectedEntry `json:"affected"`
	} `json:"data"`
}

// AnnotateVendors fills in Vendor on vulnerabilities that were matched by product name alone, so
// a report can tell "knplabs/snappy" from Google's snappy. The batch endpoint's own
// affected_range cannot be relied on, so the vendors come from the details endpoint. It returns
// how many vulnerabilities were left unannotated because of the lookup cap.
func (c *Client) AnnotateVendors(ctx context.Context, resp *CheckResponse) (skipped int, err error) {
	cache := make(map[string][]affectedEntry)
	lookups := 0

	vendorsFor := func(v Vulnerability) (string, bool, error) {
		entries, ok := cache[v.CVEID]
		if !ok {
			if lookups >= maxVendorLookups {
				return "", false, nil
			}
			lookups++
			var d detailsResponse
			if err := c.do(ctx, http.MethodGet, "/api/v1/vulnerabilities/"+url.PathEscape(v.CVEID), nil, &d); err != nil {
				var apiErr *APIError
				if asNotFound(err, &apiErr) {
					cache[v.CVEID] = nil
					return "", true, nil
				}
				return "", false, fmt.Errorf("looking up %s: %w", v.CVEID, err)
			}
			for _, rec := range d.Data {
				entries = append(entries, rec.Affected...)
			}
			cache[v.CVEID] = entries
		}
		return vendorsOf(entries, v.Product), true, nil
	}

	annotated := make(map[string]string) // CVE + product -> vendor
	annotate := func(vulns []Vulnerability) error {
		for i, v := range vulns {
			if v.Vendor != "" {
				continue
			}
			key := v.CVEID + keySep + v.Product
			vendor, seen := annotated[key]
			if !seen {
				var ok bool
				var err error
				vendor, ok, err = vendorsFor(v)
				if err != nil {
					return err
				}
				if !ok {
					skipped++
					continue
				}
				annotated[key] = vendor
			}
			vulns[i].Vendor = vendor
		}
		return nil
	}

	if err := annotate(resp.Vulnerable); err != nil {
		return skipped, err
	}
	for _, loc := range resp.ByLocation {
		if err := annotate(loc.Vulnerable); err != nil {
			return skipped, err
		}
	}
	return skipped, nil
}

// vendorsOf lists the distinct vendors an advisory names for product, comma-separated.
func vendorsOf(entries []affectedEntry, product string) string {
	set := make(map[string]bool)
	for _, e := range entries {
		if e.Vendor != "" && strings.EqualFold(e.Product, product) {
			set[e.Vendor] = true
		}
	}
	vendors := make([]string, 0, len(set))
	for v := range set {
		vendors = append(vendors, v)
	}
	sort.Strings(vendors)
	return strings.Join(vendors, ",")
}

func asNotFound(err error, target **APIError) bool {
	e, ok := err.(*APIError)
	if ok && e.StatusCode == http.StatusNotFound {
		*target = e
		return true
	}
	return false
}

// Remove drops every result for products where match returns true.
func (r *CheckResponse) Remove(match func(product string) bool) {
	keepV := r.Vulnerable[:0]
	for _, v := range r.Vulnerable {
		if !match(v.Product) {
			keepV = append(keepV, v)
		}
	}
	r.Vulnerable = keepV
	keepU := r.Unmatched[:0]
	for _, u := range r.Unmatched {
		if !match(u.Product) {
			keepU = append(keepU, u)
		}
	}
	r.Unmatched = keepU
	for loc, entry := range r.ByLocation {
		var vs []Vulnerability
		for _, v := range entry.Vulnerable {
			if !match(v.Product) {
				vs = append(vs, v)
			}
		}
		var us []UnmatchedComponent
		for _, u := range entry.Unmatched {
			if !match(u.Product) {
				us = append(us, u)
			}
		}
		if len(vs) == 0 && len(us) == 0 {
			delete(r.ByLocation, loc)
			continue
		}
		entry.Vulnerable, entry.Unmatched = vs, us
	}
}

// Merge adds the results of other to r.
func (r *CheckResponse) Merge(other *CheckResponse) {
	r.Vulnerable = append(r.Vulnerable, other.Vulnerable...)
	r.Unmatched = append(r.Unmatched, other.Unmatched...)
	for loc, entry := range other.ByLocation {
		dst := r.locationEntry(loc)
		dst.Vulnerable = append(dst.Vulnerable, entry.Vulnerable...)
		dst.Unmatched = append(dst.Unmatched, entry.Unmatched...)
	}
}
