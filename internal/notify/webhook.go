package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TadeasDitte/Svetovit/internal/state"
)

type Format int

const (
	Generic Format = iota
	Slack
	Discord
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

type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

func Count(findings []state.Finding, scope string) Counts {
	var c Counts
	for _, f := range findings {
		if scope != "" && f.Scope != scope {
			continue
		}
		switch f.Severity {
		case "CRITICAL":
			c.Critical++
		case "HIGH":
			c.High++
		case "MEDIUM":
			c.Medium++
		case "LOW":
			c.Low++
		}
	}
	return c
}

type Params struct {
	Target           string   `json:"target"`
	Mode             string   `json:"mode"`
	Depth            int      `json:"depth"` // -1 = unlimited
	Aggressivity     int      `json:"aggressivity"`
	Workers          int      `json:"workers"`
	CrossFilesystems bool     `json:"cross_filesystems"`
	SkipSystem       bool     `json:"skip_system"`
	Confidence       string   `json:"confidence"`
	MinScore         float64  `json:"min_score"`
	Severity         []string `json:"severity,omitempty"`
}

type Summary struct {
	Title    string
	Host     string
	Counts   Counts
	Duration time.Duration
	Params   Params
}

type genericPayload struct {
	Text            string  `json:"text"`
	Host            string  `json:"host"`
	Counts          Counts  `json:"counts"`
	DurationSeconds float64 `json:"duration_seconds"`
	Params          Params  `json:"params"`
}

func (s Summary) Text(format Format) string {
	title := "**" + s.Title + "**"
	if format == Slack {
		title = "*" + s.Title + "*"
	}

	return fmt.Sprintf("%s\nCRIT %d · HIGH %d · MED %d · LOW %d\nScan took %s\nParams: %s",
		title, s.Counts.Critical, s.Counts.High, s.Counts.Medium, s.Counts.Low,
		s.Duration.Round(100*time.Millisecond), s.Params)
}

func (p Params) String() string {
	depth := "unlimited"
	if p.Depth >= 0 {
		depth = strconv.Itoa(p.Depth)
	}
	parts := []string{
		"target=" + p.Target, "mode=" + p.Mode, "depth=" + depth,
		"aggressivity=" + strconv.Itoa(p.Aggressivity), "workers=" + strconv.Itoa(p.Workers),
		"confidence=" + p.Confidence,
	}
	if p.MinScore > 0 {
		parts = append(parts, "min-score="+strconv.FormatFloat(p.MinScore, 'f', -1, 64))
	}
	if len(p.Severity) > 0 {
		parts = append(parts, "severity="+strings.Join(p.Severity, ","))
	}
	if p.CrossFilesystems {
		parts = append(parts, "cross-filesystems")
	}
	if p.SkipSystem {
		parts = append(parts, "skip-system")
	}
	return strings.Join(parts, " ")
}

const (
	colorCritical = 0xE74C3C
	colorHigh     = 0xE67E22
	colorMedium   = 0xF1C40F
	colorLow      = 0x3498DB
	colorClean    = 0x2ECC71
)

func (c Counts) color() int {
	switch {
	case c.Critical > 0:
		return colorCritical
	case c.High > 0:
		return colorHigh
	case c.Medium > 0:
		return colorMedium
	case c.Low > 0:
		return colorLow
	}
	return colorClean
}

type embedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

func discordPayload(sum Summary, now time.Time) map[string]any {
	params := sum.Params.String()
	if len(params) > 1000 {
		params = params[:1000] + "…"
	}
	c := sum.Counts
	fields := []embedField{
		{"Critical", strconv.Itoa(c.Critical), true},
		{"High", strconv.Itoa(c.High), true},
		{"Medium", strconv.Itoa(c.Medium), true},
		{"Low", strconv.Itoa(c.Low), true},
		{"Scan duration", sum.Duration.Round(100 * time.Millisecond).String(), true},
		{"Host", sum.Host, true},
		{"Params", "```" + params + "```", false},
	}
	return map[string]any{"embeds": []any{map[string]any{
		"title":     sum.Title,
		"color":     c.color(),
		"fields":    fields,
		"timestamp": now.UTC().Format(time.RFC3339),
	}}}
}

func Send(ctx context.Context, client *http.Client, webhook string, sum Summary, events []state.Event) error {
	if len(events) == 0 {
		return nil
	}

	format := FormatFor(webhook)
	var payload any
	switch format {
	case Slack:
		payload = map[string]string{"text": sum.Text(format)}
	case Discord:
		payload = discordPayload(sum, time.Now())
	default:
		payload = genericPayload{
			Text: sum.Text(format), Host: sum.Host, Counts: sum.Counts,
			DurationSeconds: sum.Duration.Round(100 * time.Millisecond).Seconds(), Params: sum.Params,
		}
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
