// Package report renders a rozhanitsy.CheckResponse as human-readable text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/TadeasDitte/Svetovit/internal/rozhanitsy"
)

var severityRank = map[string]int{
	"CRITICAL": 4,
	"HIGH":     3,
	"MEDIUM":   2,
	"LOW":      1,
}

// Sections selects which parts of a CheckResponse to render: Bound is the
// vulnerable/matched components, Unbound is the components that couldn't be
// resolved against the vulnerability database's product catalog.
type Sections struct {
	Bound   bool
	Unbound bool
}

// Filter narrows down which vulnerabilities are considered relevant. A zero
// Filter matches everything.
type Filter struct {
	MinScore   float64
	Severities []string // matched case-insensitively; empty means no restriction
}

// Apply returns the subset of vulns passing f.
func (f Filter) Apply(vulns []rozhanitsy.Vulnerability) []rozhanitsy.Vulnerability {
	if f.MinScore <= 0 && len(f.Severities) == 0 {
		return vulns
	}

	allowed := make(map[string]bool, len(f.Severities))
	for _, s := range f.Severities {
		allowed[strings.ToUpper(strings.TrimSpace(s))] = true
	}

	var out []rozhanitsy.Vulnerability
	for _, v := range vulns {
		if v.CVSSScore < f.MinScore {
			continue
		}
		if len(allowed) > 0 && !allowed[strings.ToUpper(v.CVSSSeverity)] {
			continue
		}
		out = append(out, v)
	}
	return out
}

// Print writes a human-readable summary of resp to w, limited to sections.
func Print(w io.Writer, resp *rozhanitsy.CheckResponse, sections Sections) {
	fmt.Fprintf(w, "Scan checked at %s\n\n", resp.CheckedAt.Format(time.RFC3339))

	if sections.Bound {
		printVulnerable(w, resp.Vulnerable)
	}

	if sections.Unbound {
		if sections.Bound {
			fmt.Fprintln(w)
		}
		printUnmatched(w, resp.Unmatched)
	}
}

func printVulnerable(w io.Writer, vulnerable []rozhanitsy.Vulnerability) {
	if len(vulnerable) == 0 {
		fmt.Fprintln(w, "No known vulnerabilities found (matching current filters).")
		return
	}

	vulns := make([]rozhanitsy.Vulnerability, len(vulnerable))
	copy(vulns, vulnerable)
	sort.SliceStable(vulns, func(i, j int) bool {
		if vulns[i].CVSSSeverity != vulns[j].CVSSSeverity {
			return severityRank[vulns[i].CVSSSeverity] > severityRank[vulns[j].CVSSSeverity]
		}
		return vulns[i].CVSSScore > vulns[j].CVSSScore
	})

	fmt.Fprintf(w, "%d known vulnerabilit%s found:\n\n", len(vulns), plural(len(vulns)))

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tCVSS\tPRODUCT\tVERSION\tCVE\tLOCATION")
	for _, v := range vulns {
		fmt.Fprintf(tw, "%s\t%.1f\t%s\t%s\t%s\t%s\n",
			v.CVSSSeverity, v.CVSSScore, v.Product, v.InstalledVersion, v.CVEID, v.LocalID)
	}
	tw.Flush()
}

func printUnmatched(w io.Writer, unmatched []rozhanitsy.UnmatchedComponent) {
	if len(unmatched) == 0 {
		fmt.Fprintln(w, "No unmatched components.")
		return
	}

	fmt.Fprintf(w, "%d component%s could not be matched against the vulnerability database:\n",
		len(unmatched), suffix(len(unmatched)))
	for _, u := range unmatched {
		fmt.Fprintf(w, "  - %s/%s (%s)\n", u.Vendor, u.Product, u.LocalID)
	}
}

// WriteJSON writes resp as JSON to w, limited to sections.
func WriteJSON(w io.Writer, resp *rozhanitsy.CheckResponse, sections Sections) error {
	out := *resp
	if !sections.Bound {
		out.Vulnerable = nil
	}
	if !sections.Unbound {
		out.Unmatched = nil
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func suffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
