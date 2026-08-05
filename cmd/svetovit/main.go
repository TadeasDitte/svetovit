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

type cliFlags struct {
	target      string
	depth       int
	serverURL   string
	token       string
	timeout     time.Duration
	confidence  string
	minScore    float64
	severity    string
	outNormal   string
	outJSON     string
	outAll      string
	byLocations bool
	format      string
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	_ = godotenv.Load() // optional .env in cwd; real env vars still take precedence

	flags, err := parseFlags(args)
	if err != nil {
		return fail(2, err)
	}

	sections, confidenceMode, err := parseSections(flags.confidence)
	if err != nil {
		return fail(2, err)
	}

	format, err := normalizeFormat(flags.format)
	if err != nil {
		return fail(2, err)
	}
	flags.format = format

	apiComponents, err := detectComponents(flags.target, flags.depth)
	if err != nil {
		return fail(1, err)
	}

	resp, err := checkVulnerabilities(flags, apiComponents, confidenceMode)
	if err != nil {
		return fail(1, err)
	}

	if err := emitReports(flags, resp, sections); err != nil {
		return fail(1, err)
	}

	if len(resp.Vulnerable) > 0 {
		return 3
	}
	return 0
}

func fail(code int, err error) int {
	fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
	return code
}

func parseFlags(args []string) (*cliFlags, error) {
	fs := pflag.NewFlagSet("svetovit", pflag.ContinueOnError)
	f := &cliFlags{}

	fs.StringVarP(&f.target, "target", "t", ".", "path to the CMS install (or tenant directory holding several installs) to scan")
	fs.IntVarP(&f.depth, "depth", "d", scanner.UnlimitedDepth, "max directory levels below --target to search for CMS installs (0 = target only, 1 = target's immediate subdirectories, ...); default is a full recursive search")
	fs.StringVarP(&f.serverURL, "server", "s", os.Getenv("ROZHANITSY_URL"), "Rozhanitsy server base URL (env ROZHANITSY_URL)")
	fs.StringVar(&f.token, "token", os.Getenv("SCAN_TOKEN"), "Rozhanitsy scan host bearer token (env SCAN_TOKEN)")
	fs.DurationVar(&f.timeout, "timeout", 30*time.Second, "HTTP request timeout")

	fs.StringVarP(&f.confidence, "confidence", "c", "all", "which results to report: bounded (known-vulnerable), unbound (unmatched), or all")
	fs.Float64VarP(&f.minScore, "min-score", "m", 0, "only report vulnerabilities with CVSS score >= this value")
	fs.StringVar(&f.severity, "severity", "", "comma-separated CVSS severities to report, e.g. critical,high")

	fs.StringVar(&f.outNormal, "oN", "", "also write the normal-format report to this file")
	fs.StringVar(&f.outJSON, "oJ", "", "also write a JSON report to this file")
	fs.StringVar(&f.outAll, "oA", "", "also write the report to <basename>.txt and <basename>.json")

	fs.BoolVarP(&f.byLocations, "per-location", "l", false, "show report per location")
	fs.StringVarP(&f.format, "format", "f", "normal", "format output as json or quiet. quiet shows only errors")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if f.serverURL == "" {
		return nil, fmt.Errorf("--server or ROZHANITSY_URL is required")
	}
	if f.token == "" {
		return nil, fmt.Errorf("--token or SCAN_TOKEN is required")
	}

	return f, nil
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

func normalizeFormat(format string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(format))
	switch normalized {
	case "":
		return "normal", nil
	case "normal", "json", "quiet":
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid --format value %v (normal, json or quiet)", format)
	}
}

func apiConfidence(mode string) string {
	if mode == "bounded" {
		return "bounded"
	}
	return "all"
}

// detectComponents loads the detector registry, scans target for known CMS
// installs, and converts the findings into the shape the Rozhanitsy API expects.
func detectComponents(target string, depth int) ([]rozhanitsy.Component, error) {
	registry, err := detector.LoadFS(detectors.FS)
	if err != nil {
		return nil, fmt.Errorf("loading detectors: %w", err)
	}

	components, err := scanner.New(registry, depth).Scan(target)
	if err != nil {
		return nil, fmt.Errorf("scanning %s: %w", target, err)
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("no known CMS platform detected at %s", target)
	}

	apiComponents := make([]rozhanitsy.Component, len(components))
	for i, c := range components {
		apiComponents[i] = rozhanitsy.Component{
			Vendor:  c.Vendor,
			Product: c.Product,
			Version: c.Version,
			LocalID: c.LocalID,
		}
	}
	return apiComponents, nil
}

func checkVulnerabilities(flags *cliFlags, components []rozhanitsy.Component, confidenceMode string) (*rozhanitsy.CheckResponse, error) {
	client := rozhanitsy.New(flags.serverURL, flags.token)
	client.HTTP.Timeout = flags.timeout

	ctx, cancel := context.WithTimeout(context.Background(), flags.timeout*2)
	defer cancel()

	var severities []string
	if flags.severity != "" {
		severities = strings.Split(flags.severity, ",")
	}

	return client.CheckVulns(ctx, components, flags.minScore, severities, apiConfidence(confidenceMode))
}

// emitReports writes the primary report to stdout (per --format) and then to
// any of the --oN/--oJ/--oA files the user requested.
func emitReports(flags *cliFlags, resp *rozhanitsy.CheckResponse, sections report.Sections) error {
	switch flags.format {
	case "normal":
		report.Print(os.Stdout, resp, sections, flags.byLocations)
	case "json":
		report.WriteJSON(os.Stdout, resp, sections, flags.byLocations)
	case "quiet":
		// nothing
	}

	for path, write := range reportOutputs(flags, resp, sections) {
		if err := writeReportFile(path, write); err != nil {
			return err
		}
	}
	return nil
}

func reportOutputs(flags *cliFlags, resp *rozhanitsy.CheckResponse, sections report.Sections) map[string]func(io.Writer) error {
	outputs := map[string]func(io.Writer) error{}
	if flags.outNormal != "" {
		outputs[flags.outNormal] = func(w io.Writer) error { report.Print(w, resp, sections, flags.byLocations); return nil }
	}
	if flags.outJSON != "" {
		outputs[flags.outJSON] = func(w io.Writer) error { return report.WriteJSON(w, resp, sections, flags.byLocations) }
	}
	if flags.outAll != "" {
		outputs[flags.outAll+".txt"] = func(w io.Writer) error { report.Print(w, resp, sections, flags.byLocations); return nil }
		outputs[flags.outAll+".json"] = func(w io.Writer) error { return report.WriteJSON(w, resp, sections, flags.byLocations) }
	}
	return outputs
}

func writeReportFile(path string, write func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	return write(f)
}
