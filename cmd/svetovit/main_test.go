package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TadeasDitte/Svetovit/internal/report"
)

func TestParseSections(t *testing.T) {
	tests := []struct {
		in       string
		want     report.Sections
		wantNorm string
	}{
		{"", report.Sections{Bounded: true, Unbound: true}, "all"},
		{"all", report.Sections{Bounded: true, Unbound: true}, "all"},
		{"  ALL ", report.Sections{Bounded: true, Unbound: true}, "all"},
		{"bounded", report.Sections{Bounded: true}, "bounded"},
		{"Unbound", report.Sections{Unbound: true}, "unbound"},
	}
	for _, tt := range tests {
		got, norm, err := parseSections(tt.in)
		if err != nil || got != tt.want || norm != tt.wantNorm {
			t.Errorf("parseSections(%q) = %+v, %q, %v", tt.in, got, norm, err)
		}
	}

	_, _, err := parseSections("bogus")
	if err == nil || !strings.Contains(err.Error(), `"bogus"`) {
		t.Errorf("expected error naming the bad value, got %v", err)
	}
}

func TestWriteReportFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	err := writeReportFile(path, func(w io.Writer) error {
		_, err := io.WriteString(w, "hello")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "hello" {
		t.Errorf("file contains %q", data)
	}

	want := errors.New("write failed")
	if got := writeReportFile(path, func(io.Writer) error { return want }); !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	err = writeReportFile(filepath.Join(t.TempDir(), "missing", "out.txt"), func(io.Writer) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "creating") {
		t.Errorf("got %v", err)
	}
}
