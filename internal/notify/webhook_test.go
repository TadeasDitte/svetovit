package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TadeasDitte/Svetovit/internal/state"
)

func TestFormatFor(t *testing.T) {
	cases := map[string]Format{
		"https://hooks.slack.com/services/T/B/x":     Slack,
		"https://discord.com/api/webhooks/1/abc":     Discord,
		"https://discordapp.com/api/webhooks/1/abc":  Discord,
		"https://ptb.discord.com/api/webhooks/1/abc": Discord,
		"https://discord.com/channels/1":             Generic,
		"https://chat.example.com/hooks/xyz":         Generic,
		"https://hooks.slack.com.evil.example/x":     Generic,
	}
	for url, want := range cases {
		if got := FormatFor(url); got != want {
			t.Errorf("FormatFor(%s) = %v, want %v", url, got, want)
		}
	}
}

func event(kind state.Kind, cve, severity string, score float64) state.Event {
	return state.Event{Kind: kind, DaysOpen: 12, Finding: state.Finding{
		Location: "/var/www/shop", Component: "woocommerce", Version: "8.1.0", AdvisoryID: cve, Severity: severity, Score: score, FixedIn: "8.1.2", Scope: state.Apps,
	}}
}

func summary() Summary {
	return Summary{
		Title: "Svetovit scan on web1", Host: "web1",
		Counts:   Counts{Critical: 2, High: 5, Medium: 9, Low: 1},
		Duration: 12*time.Second + 430*time.Millisecond,
		Params: Params{
			Target: "/var/www", Mode: "small", Depth: -1, Aggressivity: 3, Workers: 4, Confidence: "all",
			MinScore: 7, Severity: []string{"critical", "high"},
		},
	}
}

func TestCount(t *testing.T) {
	findings := []state.Finding{
		{Severity: "CRITICAL", Scope: state.Apps},
		{Severity: "HIGH", Scope: state.Apps},
		{Severity: "HIGH", Scope: state.System},
		{Severity: "MEDIUM", Scope: state.System},
		{Severity: "LOW", Scope: state.System},
		{Severity: "UNKNOWN", Scope: state.System},
	}
	for scope, want := range map[string]Counts{
		"":           {Critical: 1, High: 2, Medium: 1, Low: 1},
		state.Apps:   {Critical: 1, High: 1},
		state.System: {High: 1, Medium: 1, Low: 1},
	} {
		if got := Count(findings, scope); got != want {
			t.Errorf("Count(scope=%q) = %+v, want %+v", scope, got, want)
		}
	}
}

func TestSummaryText(t *testing.T) {
	text := summary().Text(Slack)
	for _, want := range []string{
		"*Svetovit scan on web1*", "CRIT 2 · HIGH 5 · MED 9 · LOW 1", "Scan took 12.4s",
		"target=/var/www", "mode=small", "depth=unlimited", "aggressivity=3", "workers=4", "min-score=7", "severity=critical,high",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if md := summary().Text(Generic); !strings.HasPrefix(md, "**Svetovit scan on web1**\n") {
		t.Errorf("markdown title: %q", md)
	}
}

func TestSendPayloads(t *testing.T) {
	var got map[string]any
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = nil
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("invalid JSON: %s", body)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()

	events := []state.Event{event(state.New, "CVE-1", "HIGH", 7)}
	if err := Send(context.Background(), srv.Client(), srv.URL+"/hook", summary(), events); err != nil {
		t.Fatal(err)
	}
	if got["text"] == nil || got["host"] != "web1" || got["duration_seconds"] != 12.4 {
		t.Fatalf("generic payload: %v", got)
	}
	if _, ok := got["events"]; ok {
		t.Fatalf("payload still lists events: %v", got)
	}
	counts, _ := got["counts"].(map[string]any)
	if counts["critical"] != 2.0 || counts["high"] != 5.0 || counts["medium"] != 9.0 || counts["low"] != 1.0 {
		t.Fatalf("counts: %v", got["counts"])
	}
	params, _ := got["params"].(map[string]any)
	if params["target"] != "/var/www" || params["mode"] != "small" || params["workers"] != 4.0 || params["min_score"] != 7.0 {
		t.Fatalf("params: %v", got["params"])
	}

	got = nil
	if err := Send(context.Background(), srv.Client(), srv.URL, summary(), nil); err != nil || got != nil {
		t.Fatalf("posted with no events: %v %v", err, got)
	}

	status = http.StatusBadRequest
	err := Send(context.Background(), srv.Client(), srv.URL+"/secret-token", summary(), events)
	if err == nil {
		t.Fatal("want error for 400")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaks the webhook path: %v", err)
	}
}

func TestDiscordEmbed(t *testing.T) {
	now := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	body, err := json.Marshal(discordPayload(summary(), now))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Content string `json:"content"`
		Embeds  []struct {
			Title     string       `json:"title"`
			Color     int          `json:"color"`
			Timestamp string       `json:"timestamp"`
			Fields    []embedField `json:"fields"`
		} `json:"embeds"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Content != "" || len(got.Embeds) != 1 {
		t.Fatalf("payload: %s", body)
	}
	e := got.Embeds[0]
	if e.Title != "Svetovit scan on web1" || e.Color != colorCritical || e.Timestamp != "2026-10-12T08:00:00Z" {
		t.Fatalf("embed: %+v", e)
	}
	fields := map[string]string{}
	for _, f := range e.Fields {
		fields[f.Name] = f.Value
	}
	for name, want := range map[string]string{"Critical": "2", "High": "5", "Medium": "9", "Low": "1", "Scan duration": "12.4s", "Host": "web1"} {
		if fields[name] != want {
			t.Errorf("field %s = %q, want %q", name, fields[name], want)
		}
	}
	if !strings.Contains(fields["Params"], "target=/var/www") || !strings.Contains(fields["Params"], "severity=critical,high") {
		t.Errorf("params field: %q", fields["Params"])
	}
}

func TestEmbedColor(t *testing.T) {
	for c, want := range map[Counts]int{
		{Critical: 1, High: 1}: colorCritical,
		{High: 1, Low: 3}:      colorHigh,
		{Medium: 1, Low: 1}:    colorMedium,
		{Low: 1}:               colorLow,
		{}:                     colorClean,
	} {
		if got := c.color(); got != want {
			t.Errorf("color(%+v) = %#x, want %#x", c, got, want)
		}
	}
}
