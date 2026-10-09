package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

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

func TestText(t *testing.T) {
	text := Text([]state.Event{
		event(state.New, "CVE-LOW", "LOW", 2),
		event(state.New, "CVE-CRIT", "CRITICAL", 9.8),
		event(state.Fixed, "CVE-OLD", "HIGH", 7),
		event(state.StillOpen, "CVE-OPEN", "HIGH", 8),
	}, "Svetovit scan on web1", Slack, textLimit)

	for _, want := range []string{"*Svetovit scan on web1*", "*2 new*", "*1 resolved*", "*1 still vulnerable*", "open 12 days", "was open 12 days", "fixed in 8.1.2"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Index(text, "CVE-CRIT") > strings.Index(text, "CVE-LOW") {
		t.Errorf("critical not listed first:\n%s", text)
	}
}

func TestTextTruncates(t *testing.T) {
	var events []state.Event
	for i := 0; i < 200; i++ {
		events = append(events, event(state.New, fmt.Sprintf("CVE-%d", i), "HIGH", 7))
	}
	text := Text(events, "Svetovit scan on web1", Discord, discordLimit)
	if utf8.RuneCountInString(text) > discordLimit {
		t.Fatalf("text is %d characters", utf8.RuneCountInString(text))
	}
	if !strings.Contains(text, "more") || !strings.HasPrefix(text, "**Svetovit") {
		t.Fatalf("unexpected text:\n%s", text)
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
	if err := Send(context.Background(), srv.Client(), srv.URL+"/hook", "Svetovit scan on web1", "web1", events); err != nil {
		t.Fatal(err)
	}
	if got["text"] == nil || got["host"] != "web1" {
		t.Fatalf("generic payload: %v", got)
	}
	evs, _ := got["events"].([]any)
	if len(evs) != 1 || evs[0].(map[string]any)["advisory_id"] != "CVE-1" || evs[0].(map[string]any)["type"] != "new" || evs[0].(map[string]any)["scope"] != "apps" {
		t.Fatalf("generic events: %v", got["events"])
	}

	got = nil
	if err := Send(context.Background(), srv.Client(), srv.URL, "t", "web1", nil); err != nil || got != nil {
		t.Fatalf("posted with no events: %v %v", err, got)
	}

	status = http.StatusBadRequest
	err := Send(context.Background(), srv.Client(), srv.URL+"/secret-token", "t", "web1", events)
	if err == nil {
		t.Fatal("want error for 400")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaks the webhook path: %v", err)
	}
}
