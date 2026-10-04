package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/pflag"

	"github.com/TadeasDitte/Svetovit/detectors"
	"github.com/TadeasDitte/Svetovit/internal/detector"
	"github.com/TadeasDitte/Svetovit/internal/report"
	"github.com/TadeasDitte/Svetovit/internal/rozhanitsy"
	"github.com/TadeasDitte/Svetovit/internal/scanner"
	"github.com/TadeasDitte/Svetovit/internal/system"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	_ = godotenv.Load()

	fs := pflag.NewFlagSet("svetovit", pflag.ContinueOnError)
	target := fs.StringP("target", "t", ".", "path to the CMS install (or tenant directory holding several installs) to scan")
	depth := fs.IntP("depth", "d", scanner.UnlimitedDepth, "max directory levels below --target to search for CMS installs (0 = target only, 1 = target's immediate subdirectories, ...); default is a full recursive search")
	workers := fs.Int("workers", 0, "max concurrent filesystem operations while scanning (0 = automatic)")
	serverURL := fs.StringP("server", "S", os.Getenv("ROZHANITSY_URL"), "Rozhanitsy server base URL (env ROZHANITSY_URL)")
	token := fs.StringP("token", "T", os.Getenv("SCAN_TOKEN"), "optional Rozhanitsy bearer token (env SCAN_TOKEN); the API is public")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP request timeout")

	confidence := fs.StringP("confidence", "c", "all", "which results to report: bounded (known-vulnerable), unbound (unmatched), or all")
	minScore := fs.Float64P("min-score", "m", 0, "only report vulnerabilities with CVSS score >= this value")
	severity := fs.StringP("severity", "s", "", "comma-separated CVSS severities to report, e.g. critical,high")

	outNormal := fs.String("oN", "", "also write the normal-format report to this file")
	outJSON := fs.String("oJ", "", "also write a JSON report to this file")
	outAll := fs.String("oA", "", "also write the report to <basename>.txt and <basename>.json")

	byLocations := fs.BoolP("per-location", "l", false, "show report per location")
	format := fs.StringP("format", "f", "normal", "format output as json or quiet. quiet shows only errors")
	skipSystem := fs.Bool("skip-system", false, "don't check the host's OS packages (dpkg, rpm, apk, pacman, nix, FreeBSD pkg)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
		return 2
	}

	if *serverURL == "" {
		fmt.Fprintln(os.Stderr, "svetovit: --server or ROZHANITSY_URL is required")
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

	sc := scanner.New(registry, *depth)
	sc.Workers = *workers
	components, err := sc.Scan(*target)
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
			Vendor:    c.Vendor,
			Product:   c.Product,
			Version:   c.Version,
			Ecosystem: c.Ecosystem,
			LocalID:   c.LocalID,
		}
	}

	ctx := context.Background()

	var severities []string
	if *severity != "" {
		severities = strings.Split(*severity, ",")
	}

	resp, err := client.CheckVulns(ctx, apiComponents, *minScore, severities, confidenceMode != "bounded")
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
		return 1
	}

	annotateVendors(client, resp)

	var sys *report.System
	if !*skipSystem {
		sys, err = checkSystem(client, *minScore, severities, confidenceMode != "bounded")
		if err != nil {
			fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
			return 1
		}
	}

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "", "normal":
		report.Print(os.Stdout, resp, sys, sections, *byLocations)
	case "json":
		report.WriteJSON(os.Stdout, resp, sys, sections, *byLocations)
	case "quiet":
		// nothing
	default:
		fmt.Fprintf(os.Stderr, "svetovit: invalid --format value %v (normal, json or quiet)\n", *format)
		os.Exit(2)
	}

	outputs := map[string]func(io.Writer) error{}
	if *outNormal != "" {
		outputs[*outNormal] = func(w io.Writer) error { report.Print(w, resp, sys, sections, *byLocations); return nil }
	}
	if *outJSON != "" {
		outputs[*outJSON] = func(w io.Writer) error { return report.WriteJSON(w, resp, sys, sections, *byLocations) }
	}
	if *outAll != "" {
		outputs[*outAll+".txt"] = func(w io.Writer) error { report.Print(w, resp, sys, sections, *byLocations); return nil }
		outputs[*outAll+".json"] = func(w io.Writer) error { return report.WriteJSON(w, resp, sys, sections, *byLocations) }
	}
	for path, write := range outputs {
		if err := writeReportFile(path, write); err != nil {
			fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
			return 1
		}
	}

	if len(resp.Vulnerable) > 0 || (sys != nil && len(sys.Response.Vulnerable) > 0) {
		return 3
	}
	return 0
}

// checkSystem checks the host's OS packages in a request of their own. Hosts without a
// supported package manager are skipped with a notice rather than failing the scan.
func checkSystem(client *rozhanitsy.Client, minScore float64, severities []string, includeLow bool) (*report.System, error) {
	env, err := system.Detect()
	if errors.Is(err, system.ErrUnsupported) {
		fmt.Fprintf(os.Stderr, "svetovit: skipping system packages: %v\n", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("detecting operating system: %w", err)
	}

	packages, err := env.Packages()
	if err != nil {
		return nil, fmt.Errorf("listing %s packages: %w", env.Manager, err)
	}

	components := make([]rozhanitsy.Component, len(packages))
	for i, p := range packages {
		components[i] = rozhanitsy.Component{
			Product:   p.Name,
			Version:   p.Version,
			Ecosystem: env.Ecosystem,
			LocalID:   env.Source(),
			NVDOnly:   env.Ecosystem == "",
		}
	}

	resp, err := client.CheckVulns(context.Background(), components, minScore, severities, includeLow)
	if err != nil {
		return nil, fmt.Errorf("checking system packages: %w", err)
	}

	if env.Manager == system.Nix {
		resp = refineWithNixCPEs(client, components, resp, minScore, severities, includeLow)
	}
	annotateVendors(client, resp)

	return &report.System{Name: env.Name, Ecosystem: env.Ecosystem, Response: resp}, nil
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

func writeReportFile(path string, write func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	return write(f)
}

// refineWithNixCPEs re-checks flagged NixOS packages under the exact vendor/product nixpkgs records
// for them. A bare name like "orc" also matches unrelated NVD products (Apache ORC); the CPE
// picks the right one. Packages nixpkgs has no CPE for keep their bare-name results.
func refineWithNixCPEs(client *rozhanitsy.Client, components []rozhanitsy.Component, resp *rozhanitsy.CheckResponse, minScore float64, severities []string, includeLow bool) *rozhanitsy.CheckResponse {
	flagged := make(map[string]bool)
	for _, v := range resp.Vulnerable {
		flagged[v.Product] = true
	}
	names := make([]string, 0, len(flagged))
	for name := range flagged {
		names = append(names, name)
	}
	sort.Strings(names)

	cpes, err := system.NixCPEs(names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v; keeping name-only matches\n", err)
		return resp
	}
	if len(cpes) == 0 {
		return resp
	}

	var refined []rozhanitsy.Component
	for _, c := range components {
		if cpe, ok := cpes[c.Product]; ok {
			c.Vendor, c.Product = cpe.Vendor, cpe.Product
			refined = append(refined, c)
		}
	}
	rechecked, err := client.CheckVulns(context.Background(), refined, minScore, severities, includeLow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: rechecking with nixpkgs CPEs: %v; keeping name-only matches\n", err)
		return resp
	}

	resp.Remove(func(product string) bool { _, ok := cpes[product]; return ok })
	resp.Merge(rechecked)
	return resp
}

// annotateVendors names the vendor behind each name-only match, so same-named products differ in the report.
func annotateVendors(client *rozhanitsy.Client, resp *rozhanitsy.CheckResponse) {
	skipped, err := client.AnnotateVendors(context.Background(), resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: vendor lookup: %v\n", err)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "svetovit: vendor not looked up for %d findings (lookup limit)\n", skipped)
	}
}
