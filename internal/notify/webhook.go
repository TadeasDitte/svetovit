package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/TadeasDitte/Svetovit/internal/state"
)

type Format int

const (
	Generic Format = iota
	Slack
	Discord
)

const (
	discordLimit = 2000
	textLimit    = 3500
)

func FormatFor(webhook string) Format {
	u, err := url.Parse(webhook)
	if err != nil {
		return Generic
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case host == "hooks.slack.com":
		return Slack
	case (host == "discord.com" || host == "discordapp.com" || strings.HasSuffix(host, ".discord.com")) &&
		strings.HasPrefix(u.Path, "/api/webhooks/"):
		return Discord
	}
	return Generic
}

type genericPayload struct {
	Text   string        `json:"text"`
	Host   string        `json:"host"`
	Events []state.Event `json:"events"`
}

func Send(ctx context.Context, client *http.Client, webhook, host string, events []state.Event) error {
	if len(events) == 0 {
		return nil
	}

	format := FormatFor(webhook)
	var payload any
	switch format {
	case Slack:
		payload = map[string]string{"text": Text(events, host, format, textLimit)}
	case Discord:
		payload = map[string]string{"content": Text(events, host, format, discordLimit)}
	default:
		payload = genericPayload{Text: Text(events, host, format, textLimit), Host: host, Events: events}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: posting to %s: %w", redact(webhook), unwrapURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("notify: %s answered %s: %s", redact(webhook), resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func redact(webhook string) string {
	u, err := url.Parse(webhook)
	if err != nil {
		return "webhook"
	}
	return u.Scheme + "://" + u.Host
}

func unwrapURLError(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err
	}
	return err
}

var severityRank = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

type section struct {
	kind   state.Kind
	icon   string
	header string
}

var sections = []section{
	{state.New, "🔴", "new"},
	{state.Current, "⚠️", "open"},
	{state.StillOpen, "⏰", "still vulnerable"},
	{state.Fixed, "✅", "resolved"},
	{state.Removed, "🗑️", "removed (location no longer exists)"},
}

func Text(events []state.Event, host string, format Format, limit int) string {
	byKind := make(map[state.Kind][]state.Event)
	for _, ev := range events {
		byKind[ev.Kind] = append(byKind[ev.Kind], ev)
	}

	bold := func(s string) string {
		if format == Slack {
			return "*" + s + "*"
		}
		return "**" + s + "**"
	}

	var b strings.Builder
	b.WriteString(bold("Svetovit scan on "+host) + "\n")
	remaining := len(events)
	for _, sec := range sections {
		evs := byKind[sec.kind]
		if len(evs) == 0 {
			continue
		}
		sortEvents(evs)
		header := fmt.Sprintf("\n%s %s\n", sec.icon, bold(fmt.Sprintf("%d %s", len(evs), sec.header)))
		for i, ev := range evs {
			line := "• " + describe(ev) + "\n"
			if i == 0 {
				line = header + line
			}
			more := fmt.Sprintf("…and %d more", remaining)
			if b.Len()+len(line)+len(more) > limit {
				b.WriteString(more)
				return b.String()
			}
			b.WriteString(line)
			remaining--
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func sortEvents(evs []state.Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		a, b := evs[i], evs[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Location < b.Location
	})
}

func describe(ev state.Event) string {
	s := fmt.Sprintf("%s %.1f %s %s %s (%s)", ev.Severity, ev.Score, ev.Component, ev.Version, ev.AdvisoryID, ev.Location)
	switch ev.Kind {
	case state.New, state.Current, state.StillOpen:
		if ev.FixedIn != "" {
			s += ", fixed in " + ev.FixedIn
		}
	}
	switch ev.Kind {
	case state.StillOpen:
		s += fmt.Sprintf(", open %s", daysText(ev.DaysOpen))
	case state.Fixed, state.Removed:
		s += fmt.Sprintf(", was open %s", daysText(ev.DaysOpen))
	}
	return s
}

func daysText(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}
