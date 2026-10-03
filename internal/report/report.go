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

type Sections struct {
	Bounded bool
	Unbound bool
}

type Filter struct {
	MinScore   float64
	Severities []string
}

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

// System is the result of checking the host's OS packages, reported in its own block.
type System struct {
	Name      string
	Ecosystem string
	Response  *rozhanitsy.CheckResponse
}

func Print(w io.Writer, resp *rozhanitsy.CheckResponse, system *System, sections Sections, byLocations bool) {
	fmt.Fprintf(w, "Scan checked at %s\n\n", resp.CheckedAt.Format(time.RFC3339))

	printApplications(w, resp, sections, byLocations)

	if system != nil {
		fmt.Fprintf(w, "\nSystem packages: %s (%s)\n\n", system.Name, system.Ecosystem)
		if sections.Bounded {
			printVulnerable(w, system.Response.Vulnerable, true)
		}
		if sections.Unbound {
			if sections.Bounded {
				fmt.Fprintln(w)
			}
			// Most OS packages have no advisories at all, so listing them would drown the report.
			fmt.Fprintf(w, "%d package%s could not be matched against the vulnerability database (see JSON output for the list).\n",
				len(system.Response.Unmatched), suffix(len(system.Response.Unmatched)))
		}
	}
}

func printApplications(w io.Writer, resp *rozhanitsy.CheckResponse, sections Sections, byLocations bool) {
	if byLocations {
		if len(resp.ByLocation) == 0 {
			fmt.Fprintln(w, "No locations to report (matching current filters).")
			return
		}

		paths := make([]string, 0, len(resp.ByLocation))
		for path := range resp.ByLocation {
			paths = append(paths, path)
		}
		sort.Strings(paths)

		for _, path := range paths {
			loc := resp.ByLocation[path]
			fmt.Fprintf(w, "Location: %s\n", path)
			if sections.Bounded {
				printVulnerable(w, loc.Vulnerable, true)
			}

			if sections.Unbound {
				if sections.Bounded {
					fmt.Fprintln(w)
				}
				printUnmatched(w, loc.Unmatched)
			}

			fmt.Fprintln(w)
		}
	} else {
		if sections.Bounded {
			printVulnerable(w, resp.Vulnerable, false)
		}

		if sections.Unbound {
			if sections.Bounded {
				fmt.Fprintln(w)
			}
			printUnmatched(w, resp.Unmatched)
		}
	}
}

func printVulnerable(w io.Writer, vulnerable []rozhanitsy.Vulnerability, omitLocation bool) {
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
	if omitLocation {
		fmt.Fprintln(tw, "SEVERITY\tCVSS\tPRODUCT\tVERSION\tCVE")
		for _, v := range vulns {
			fmt.Fprintf(tw, "%s\t%.1f\t%s\t%s\t%s\n",
				v.CVSSSeverity, v.CVSSScore, v.Product, v.InstalledVersion, v.CVEID)
		}
	} else {
		fmt.Fprintln(tw, "SEVERITY\tCVSS\tPRODUCT\tVERSION\tCVE\tLOCATION(S)")
		for _, v := range vulns {
			fmt.Fprintf(tw, "%s\t%.1f\t%s\t%s\t%s\t%s\n",
				v.CVSSSeverity, v.CVSSScore, v.Product, v.InstalledVersion, v.CVEID, v.LocalID)
		}
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

type jsonReport struct {
	rozhanitsy.CheckResponse
	System *jsonSystem `json:"system,omitempty"`
}

type jsonSystem struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	rozhanitsy.CheckResponse
}

func WriteJSON(w io.Writer, resp *rozhanitsy.CheckResponse, system *System, sections Sections, byLocations bool) error {
	out := jsonReport{CheckResponse: filterSections(resp, sections, byLocations)}
	if system != nil {
		out.System = &jsonSystem{
			Name:          system.Name,
			Ecosystem:     system.Ecosystem,
			CheckResponse: filterSections(system.Response, sections, false),
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func filterSections(resp *rozhanitsy.CheckResponse, sections Sections, byLocations bool) rozhanitsy.CheckResponse {
	out := *resp
	if byLocations {
		out.Vulnerable = nil
		out.Unmatched = nil

		filtered := make(map[string]*rozhanitsy.LocationReport, len(out.ByLocation))
		for loc, report := range out.ByLocation {
			r := *report
			if !sections.Bounded {
				r.Vulnerable = nil
			}
			if !sections.Unbound {
				r.Unmatched = nil
			}
			filtered[loc] = &r
		}
		out.ByLocation = filtered
	} else {
		out.ByLocation = nil
		if sections.Bounded && out.Vulnerable == nil {
			out.Vulnerable = []rozhanitsy.Vulnerability{}
		} else if !sections.Bounded {
			out.Vulnerable = nil
		}
		if sections.Unbound && out.Unmatched == nil {
			out.Unmatched = []rozhanitsy.UnmatchedComponent{}
		} else if !sections.Unbound {
			out.Unmatched = nil
		}
	}
	return out
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
