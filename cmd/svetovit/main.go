// Command svetovit scans a local CMS install for its platform and plugin
// versions, then checks them against a Rozhanitsy server for known CVEs.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/TadeasDitte/Svetovit/detectors"
	"github.com/TadeasDitte/Svetovit/internal/detector"
	"github.com/TadeasDitte/Svetovit/internal/report"
	"github.com/TadeasDitte/Svetovit/internal/rozhanitsy"
	"github.com/TadeasDitte/Svetovit/internal/scanner"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("svetovit", flag.ContinueOnError)
	target := fs.String("target", ".", "path to the CMS install (or tenant directory holding several installs) to scan")
	serverURL := fs.String("server", os.Getenv("ROZHANITSY_URL"), "Rozhanitsy server base URL (env ROZHANITSY_URL)")
	token := fs.String("token", os.Getenv("SCAN_TOKEN"), "Rozhanitsy scan host bearer token (env SCAN_TOKEN)")
	tenantID := fs.String("tenant", "", "optional tenant ID to scope the check")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP request timeout")

	show := fs.String("show", "all", "which results to report: bound (known-vulnerable), unbound (unmatched), or all")
	minScore := fs.Float64("min-score", 0, "only report vulnerabilities with CVSS score >= this value")
	severity := fs.String("severity", "", "comma-separated CVSS severities to report, e.g. critical,high")

	outNormal := fs.String("oN", "", "also write the normal-format report to this file")
	outJSON := fs.String("oJ", "", "also write a JSON report to this file")
	outAll := fs.String("oA", "", "also write the report to <basename>.txt and <basename>.json")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *serverURL == "" {
		fmt.Fprintln(os.Stderr, "svetovit: -server or ROZHANITSY_URL is required")
		return 2
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "svetovit: -token or SCAN_TOKEN is required")
		return 2
	}

	sections, err := parseSections(*show)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
		return 2
	}

	registry, err := detector.LoadFS(detectors.FS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: loading detectors: %v\n", err)
		return 1
	}

	components, err := scanner.New(registry).Scan(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: scanning %s: %v\n", *target, err)
		return 1
	}
	if len(components) == 0 {
		fmt.Fprintf(os.Stderr, "svetovit: no known CMS platform detected at %s\n", *target)
		return 1
	}

	client := rozhanitsy.New(*serverURL, *token)
	client.HTTP.Timeout = *timeout

	apiComponents := make([]rozhanitsy.Component, len(components))
	for i, c := range components {
		apiComponents[i] = rozhanitsy.Component{
			Vendor:  c.Vendor,
			Product: c.Product,
			Version: c.Version,
			LocalID: c.LocalID,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout*2)
	defer cancel()

	resp, err := client.CheckVulns(ctx, *tenantID, apiComponents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
		return 1
	}

	var severities []string
	if *severity != "" {
		severities = strings.Split(*severity, ",")
	}
	resp.Vulnerable = (report.Filter{MinScore: *minScore, Severities: severities}).Apply(resp.Vulnerable)

	report.Print(os.Stdout, resp, sections)

	outputs := map[string]func(io.Writer) error{}
	if *outNormal != "" {
		outputs[*outNormal] = func(w io.Writer) error { report.Print(w, resp, sections); return nil }
	}
	if *outJSON != "" {
		outputs[*outJSON] = func(w io.Writer) error { return report.WriteJSON(w, resp, sections) }
	}
	if *outAll != "" {
		outputs[*outAll+".txt"] = func(w io.Writer) error { report.Print(w, resp, sections); return nil }
		outputs[*outAll+".json"] = func(w io.Writer) error { return report.WriteJSON(w, resp, sections) }
	}
	for path, write := range outputs {
		if err := writeReportFile(path, write); err != nil {
			fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
			return 1
		}
	}

	if len(resp.Vulnerable) > 0 {
		return 3
	}
	return 0
}

func parseSections(show string) (report.Sections, error) {
	switch strings.ToLower(strings.TrimSpace(show)) {
	case "bound":
		return report.Sections{Bound: true}, nil
	case "unbound":
		return report.Sections{Unbound: true}, nil
	case "all", "":
		return report.Sections{Bound: true, Unbound: true}, nil
	default:
		return report.Sections{}, fmt.Errorf("invalid -show value %q (want bound, unbound, or all)", show)
	}
}

func writeReportFile(path string, write func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	return write(f)
}
