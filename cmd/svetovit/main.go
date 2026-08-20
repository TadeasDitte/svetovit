package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/pflag"

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
	_ = godotenv.Load()

	fs := pflag.NewFlagSet("svetovit", pflag.ContinueOnError)
	target := fs.StringP("target", "t", ".", "path to the CMS install (or tenant directory holding several installs) to scan")
	depth := fs.IntP("depth", "d", scanner.UnlimitedDepth, "max directory levels below --target to search for CMS installs (0 = target only, 1 = target's immediate subdirectories, ...); default is a full recursive search")
	serverURL := fs.StringP("server", "S", os.Getenv("ROZHANITSY_URL"), "Rozhanitsy server base URL (env ROZHANITSY_URL)")
	token := fs.StringP("token", "T", os.Getenv("SCAN_TOKEN"), "Rozhanitsy scan host bearer token (env SCAN_TOKEN)")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP request timeout")

	confidence := fs.StringP("confidence", "c", "all", "which results to report: bounded (known-vulnerable), unbound (unmatched), or all")
	minScore := fs.Float64P("min-score", "m", 0, "only report vulnerabilities with CVSS score >= this value")
	severity := fs.StringP("severity", "s", "", "comma-separated CVSS severities to report, e.g. critical,high")

	outNormal := fs.String("oN", "", "also write the normal-format report to this file")
	outJSON := fs.String("oJ", "", "also write a JSON report to this file")
	outAll := fs.String("oA", "", "also write the report to <basename>.txt and <basename>.json")

	byLocations := fs.BoolP("per-location", "l", false, "show report per location")
	format := fs.StringP("format", "f", "normal", "format output as json or quiet. quiet shows only errors")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
		return 2
	}

	if *serverURL == "" {
		fmt.Fprintln(os.Stderr, "svetovit: --server or ROZHANITSY_URL is required")
		return 2
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "svetovit: --token or SCAN_TOKEN is required")
		return 2
	}

	sections, confidenceMode, err := parseSections(*confidence)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
		return 2
	}

	registry, err := detector.LoadFS(detectors.FS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: loading detectors: %v\n", err)
		return 1
	}

	components, err := scanner.New(registry, *depth).Scan(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: scanning %s: %v\n", *target, err)
		return 1
	}
	if len(components) == 0 {
		fmt.Fprintf(os.Stderr, "svetovit: no known platform detected at %s\n", *target)
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

	var severities []string
	if *severity != "" {
		severities = strings.Split(*severity, ",")
	}

	resp, err := client.CheckVulns(ctx, apiComponents, *minScore, severities, apiConfidence(confidenceMode))
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
		return 1
	}

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "", "normal":
		report.Print(os.Stdout, resp, sections, *byLocations)
	case "json":
		report.WriteJSON(os.Stdout, resp, sections, *byLocations)
	case "quiet":
		// nothing
	default:
		fmt.Fprintf(os.Stderr, "svetovit: invalid --format value %v (normal, json or quiet)\n", *format)
		os.Exit(2)
	}

	outputs := map[string]func(io.Writer) error{}
	if *outNormal != "" {
		outputs[*outNormal] = func(w io.Writer) error { report.Print(w, resp, sections, *byLocations); return nil }
	}
	if *outJSON != "" {
		outputs[*outJSON] = func(w io.Writer) error { return report.WriteJSON(w, resp, sections, *byLocations) }
	}
	if *outAll != "" {
		outputs[*outAll+".txt"] = func(w io.Writer) error { report.Print(w, resp, sections, *byLocations); return nil }
		outputs[*outAll+".json"] = func(w io.Writer) error { return report.WriteJSON(w, resp, sections, *byLocations) }
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

func parseSections(confidence string) (report.Sections, string, error) {
	normalized := strings.ToLower(strings.TrimSpace(confidence))
	if normalized == "" {
		normalized = "all"
	}
	switch normalized {
	case "bounded":
		return report.Sections{Bounded: true}, normalized, nil
	case "unbound":
		return report.Sections{Unbound: true}, normalized, nil
	case "all":
		return report.Sections{Bounded: true, Unbound: true}, normalized, nil
	default:
		return report.Sections{}, "", fmt.Errorf("invalid --confidence value %q (want bounded, unbound, or all)", confidence)
	}
}

func apiConfidence(mode string) string {
	if mode == "bounded" {
		return "bounded"
	}
	return "all"
}

func writeReportFile(path string, write func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	return write(f)
}
