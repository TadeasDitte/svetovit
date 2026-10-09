package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/pflag"

	"github.com/TadeasDitte/Svetovit/detectors"
	"github.com/TadeasDitte/Svetovit/internal/detector"
	"github.com/TadeasDitte/Svetovit/internal/notify"
	"github.com/TadeasDitte/Svetovit/internal/report"
	"github.com/TadeasDitte/Svetovit/internal/rozhanitsy"
	"github.com/TadeasDitte/Svetovit/internal/scanner"
	"github.com/TadeasDitte/Svetovit/internal/state"
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
	aggressivity := fs.IntP("aggressivity", "a", scanner.DefaultAggressivity, "scan speed, 1 (gentlest) to 5 (fastest): 1 = 1 worker at <=100 fs ops/s, 2 = 2 workers at <=500 ops/s, 3 = 4 workers, 4 = 8, 5 = 16")
	workers := fs.Int("workers", scanner.DefaultWorkers, "override the number of concurrent filesystem operations set by --aggressivity")
	mode := fs.String("mode", "small", "how much of an install to search: small (plugins and their lock files only), half (everything inside installs, including nested installs, except upload/cache dirs), full (everything)")
	crossFS := fs.Bool("cross-filesystems", false, "descend into directories mounted from other filesystems (NFS, backup mounts, ...) below --target")
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

	statePath := fs.String("state", os.Getenv("SVETOVIT_STATE"), "keep findings in a SQLite database at this path (env SVETOVIT_STATE) to report what is new, fixed or still open; --state alone uses "+state.DefaultPath())
	fs.Lookup("state").NoOptDefVal = "default"
	notifyURL := fs.String("notify-url", os.Getenv("SVETOVIT_NOTIFY_URL"), "post findings to this webhook (env SVETOVIT_NOTIFY_URL): Slack, Discord, or generic JSON; with --state only changes are posted")
	notifySystemURL := fs.String("notify-system-url", os.Getenv("SVETOVIT_NOTIFY_SYSTEM_URL"), "like --notify-url, but only the host's OS package findings, e.g. for the admins' channel (env SVETOVIT_NOTIFY_SYSTEM_URL)")
	notifyAppsURL := fs.String("notify-apps-url", os.Getenv("SVETOVIT_NOTIFY_APPS_URL"), "like --notify-url, but only findings under --target (hosted sites), not OS packages (env SVETOVIT_NOTIFY_APPS_URL)")
	renotifyFlag := fs.String("renotify", "", "with --state, remind about critical and high findings still open this long after the last message, e.g. 7d or 12h")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "svetovit: unexpected argument %q (a path for --state is given as --state=<path>)\n", fs.Arg(0))
		return 2
	}

	if *skipSystem && *notifySystemURL != "" {
		fmt.Fprintln(os.Stderr, "svetovit: --notify-system-url needs the OS packages checked; drop --skip-system")
		return 2
	}

	renotify, err := parseDays(*renotifyFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: invalid --renotify value: %v\n", err)
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

	scanMode, err := scanner.ParseMode(*mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
		return 2
	}
	scanWorkers, opsPerSecond, err := scanner.Aggressivity(*aggressivity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
		return 2
	}
	if fs.Changed("workers") {
		scanWorkers = *workers
	}

	registry, err := detector.LoadFS(detectors.FS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svetovit: loading detectors: %v\n", err)
		return 1
	}

	var store *state.Store
	if *statePath == "default" {
		*statePath = state.DefaultPath()
	}
	if *statePath != "" {
		store, err = state.Open(*statePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
			return 1
		}
		defer store.Close()
	}

	sc := scanner.New(registry, *depth)
	sc.Workers = scanWorkers
	sc.OpsPerSecond = opsPerSecond
	sc.Mode = scanMode
	sc.CrossFilesystems = *crossFS
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
			Vendor:           c.Vendor,
			Product:          c.Product,
			Version:          c.Version,
			Ecosystem:        c.Ecosystem,
			LocalID:          c.LocalID,
			ResolveAmbiguous: true,
			Platform:         c.Platform,
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

	var sys *report.System
	if !*skipSystem {
		sys, err = checkSystem(client, *minScore, severities, confidenceMode != "bounded")
		if err != nil {
			fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
			return 1
		}
	}

	now := time.Now()
	findings := collectFindings(resp, sys)
	var changes *state.Changes
	if store != nil {
		scanned := make(map[string]bool, len(components)+1)
		for _, c := range components {
			scanned[c.LocalID] = true
		}
		if sys != nil {
			scanned[sys.Source] = true
		}
		absTarget, _ := filepath.Abs(*target)
		changes, err = store.Sync(state.Run{
			Now:        now,
			Findings:   findings,
			Scanned:    scanned,
			TargetRoot: absTarget,
			InScope:    report.Filter{MinScore: *minScore, Severities: severities}.Matches,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
			return 1
		}
	}

	host, _ := os.Hostname()
	channels := []struct{ name, scope, url, title string }{
		{"all", "", *notifyURL, "Svetovit scan on " + host},
		{state.System, state.System, *notifySystemURL, "Svetovit: server packages on " + host},
		{state.Apps, state.Apps, *notifyAppsURL, "Svetovit: hosted sites on " + host},
	}
	httpClient := &http.Client{Timeout: *timeout}
	for _, ch := range channels {
		if ch.url == "" {
			continue
		}
		var events []state.Event
		if store != nil {
			if events, err = store.Pending(ch.name, ch.scope, now, renotify); err != nil {
				fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
				return 1
			}
		} else {
			for _, f := range findings {
				if ch.scope == "" || f.Scope == ch.scope {
					events = append(events, state.Event{Kind: state.Current, Finding: f})
				}
			}
		}
		if err := notify.Send(ctx, httpClient, ch.url, ch.title, host, events); err != nil {
			// Not fatal: the events stay pending and are sent with the next run.
			fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
			continue
		}
		if store != nil {
			if err := store.MarkDelivered(ch.name, events, now); err != nil {
				fmt.Fprintf(os.Stderr, "svetovit: %v\n", err)
				return 1
			}
		}
	}

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "", "normal":
		report.Print(os.Stdout, resp, sys, changes, sections, *byLocations)
	case "json":
		report.WriteJSON(os.Stdout, resp, sys, changes, sections, *byLocations)
	case "quiet":
		// nothing
	default:
		fmt.Fprintf(os.Stderr, "svetovit: invalid --format value %v (normal, json or quiet)\n", *format)
		os.Exit(2)
	}

	outputs := map[string]func(io.Writer) error{}
	if *outNormal != "" {
		outputs[*outNormal] = func(w io.Writer) error { report.Print(w, resp, sys, changes, sections, *byLocations); return nil }
	}
	if *outJSON != "" {
		outputs[*outJSON] = func(w io.Writer) error { return report.WriteJSON(w, resp, sys, changes, sections, *byLocations) }
	}
	if *outAll != "" {
		outputs[*outAll+".txt"] = func(w io.Writer) error { report.Print(w, resp, sys, changes, sections, *byLocations); return nil }
		outputs[*outAll+".json"] = func(w io.Writer) error { return report.WriteJSON(w, resp, sys, changes, sections, *byLocations) }
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

	return &report.System{Name: env.Name, Ecosystem: env.Ecosystem, Source: env.Source(), Response: resp}, nil
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

func collectFindings(resp *rozhanitsy.CheckResponse, sys *report.System) []state.Finding {
	var findings []state.Finding
	add := func(r *rozhanitsy.CheckResponse, scope string) {
		for loc, entry := range r.ByLocation {
			for _, v := range entry.Vulnerable {
				component := v.Product
				if v.Vendor != "" && v.Vendor != v.Product {
					component = v.Vendor + "/" + v.Product
				}
				findings = append(findings, state.Finding{
					Location:   loc,
					Component:  component,
					Version:    v.InstalledVersion,
					AdvisoryID: v.CVEID,
					Severity:   v.CVSSSeverity,
					Score:      v.CVSSScore,
					FixedIn:    v.FixedIn,
					Scope:      scope,
				})
			}
		}
	}
	add(resp, state.Apps)
	if sys != nil {
		add(sys.Response, state.System)
	}
	return findings
}

func parseDays(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseFloat(n, 64)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("%q is not a number of days", s)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%q is not a duration like 7d or 12h", s)
	}
	return d, nil
}

func writeReportFile(path string, write func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	return write(f)
}

func refineWithNixCPEs(client *rozhanitsy.Client, components []rozhanitsy.Component, resp *rozhanitsy.CheckResponse, minScore float64, severities []string, includeLow bool) *rozhanitsy.CheckResponse {
	flagged := make(map[string]bool)
	for _, v := range resp.Vulnerable {
		flagged[v.Product] = true
	}
	for _, u := range resp.Unmatched {
		if u.Ambiguous {
			flagged[u.Product] = true
		}
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
