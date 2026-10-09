package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sub", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func finding(loc, cve, severity string) Finding {
	return Finding{Location: loc, Component: "plugin", Version: "1.0", AdvisoryID: cve, Severity: severity, Score: 9}
}

func doSync(t *testing.T, s *Store, run Run) *Changes {
	t.Helper()
	c, err := s.Sync(run)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func scanned(locs ...string) map[string]bool {
	m := make(map[string]bool)
	for _, l := range locs {
		m[l] = true
	}
	return m
}

var day0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestNewSeenFixed(t *testing.T) {
	s := openTemp(t)
	f := finding("/www/a", "CVE-1", "HIGH")

	c := doSync(t, s, Run{Now: day0, Findings: []Finding{f}, Scanned: scanned("/www/a")})
	if len(c.New) != 1 || c.Open != 1 {
		t.Fatalf("first run: %+v", c)
	}

	c = doSync(t, s, Run{Now: day0.AddDate(0, 0, 1), Findings: []Finding{f}, Scanned: scanned("/www/a")})
	if len(c.New) != 0 || c.Open != 1 {
		t.Fatalf("second run: %+v", c)
	}

	// One clean scan is not enough.
	c = doSync(t, s, Run{Now: day0.AddDate(0, 0, 2), Scanned: scanned("/www/a")})
	if len(c.Fixed) != 0 || c.Open != 1 {
		t.Fatalf("first clean run: %+v", c)
	}
	c = doSync(t, s, Run{Now: day0.AddDate(0, 0, 3), Scanned: scanned("/www/a")})
	if len(c.Fixed) != 1 || c.Open != 0 || c.Fixed[0].DaysOpen != 3 {
		t.Fatalf("second clean run: %+v", c)
	}
}

func TestFlappingResetsCleanRuns(t *testing.T) {
	s := openTemp(t)
	f := finding("/www/a", "CVE-1", "HIGH")
	sc := scanned("/www/a")

	doSync(t, s, Run{Now: day0, Findings: []Finding{f}, Scanned: sc})
	doSync(t, s, Run{Now: day0, Scanned: sc})
	doSync(t, s, Run{Now: day0, Findings: []Finding{f}, Scanned: sc})
	if c := doSync(t, s, Run{Now: day0, Scanned: sc}); len(c.Fixed) != 0 {
		t.Fatalf("resolved although the finding came back in between: %+v", c)
	}
}

func TestUnscannedLocationsAreLeftAlone(t *testing.T) {
	s := openTemp(t)
	root := t.TempDir()
	existing := filepath.Join(root, "unreadable")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	findings := []Finding{
		finding(existing, "CVE-1", "HIGH"),       // below the target, exists, not scanned
		finding("/elsewhere/x", "CVE-2", "HIGH"), // another target
	}
	doSync(t, s, Run{Now: day0, Findings: findings, Scanned: scanned(existing, "/elsewhere/x")})

	for i := 0; i < 3; i++ {
		c := doSync(t, s, Run{Now: day0, Scanned: scanned(), TargetRoot: root})
		if len(c.Fixed)+len(c.Removed) != 0 || c.Open != 2 {
			t.Fatalf("run %d resolved findings it did not look at: %+v", i, c)
		}
	}
}

func TestVanishedLocationIsRemoved(t *testing.T) {
	s := openTemp(t)
	root := t.TempDir()
	loc := filepath.Join(root, "deleted-site")
	doSync(t, s, Run{Now: day0, Findings: []Finding{finding(loc, "CVE-1", "HIGH")}, Scanned: scanned(loc), TargetRoot: root})

	doSync(t, s, Run{Now: day0, Scanned: scanned(), TargetRoot: root})
	c := doSync(t, s, Run{Now: day0, Scanned: scanned(), TargetRoot: root})
	if len(c.Removed) != 1 || len(c.Fixed) != 0 {
		t.Fatalf("want removed, got %+v", c)
	}
}

func TestOutOfScopeFindingsAreNotResolved(t *testing.T) {
	s := openTemp(t)
	sc := scanned("/www/a")
	doSync(t, s, Run{Now: day0, Findings: []Finding{finding("/www/a", "CVE-1", "MEDIUM")}, Scanned: sc})

	onlyCritical := func(severity string, _ float64) bool { return severity == "CRITICAL" }
	for i := 0; i < 3; i++ {
		if c := doSync(t, s, Run{Now: day0, Scanned: sc, InScope: onlyCritical}); len(c.Fixed) != 0 {
			t.Fatalf("filtered-out finding resolved: %+v", c)
		}
	}
}

func TestReopen(t *testing.T) {
	s := openTemp(t)
	f := finding("/www/a", "CVE-1", "HIGH")
	sc := scanned("/www/a")
	doSync(t, s, Run{Now: day0, Findings: []Finding{f}, Scanned: sc})
	doSync(t, s, Run{Now: day0, Scanned: sc})
	doSync(t, s, Run{Now: day0, Scanned: sc})

	c := doSync(t, s, Run{Now: day0.AddDate(0, 0, 5), Findings: []Finding{f}, Scanned: sc})
	if len(c.New) != 1 || c.Open != 1 {
		t.Fatalf("want reopened, got %+v", c)
	}
}

func kinds(events []Event) map[Kind]int {
	m := make(map[Kind]int)
	for _, e := range events {
		m[e.Kind]++
	}
	return m
}

func TestPendingAndRenotify(t *testing.T) {
	s := openTemp(t)
	sc := scanned("/www/a")
	crit := finding("/www/a", "CVE-1", "CRITICAL")
	med := finding("/www/a", "CVE-2", "MEDIUM")
	doSync(t, s, Run{Now: day0, Findings: []Finding{crit, med}, Scanned: sc})

	ev, err := s.Pending(day0, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(ev); k[New] != 2 || len(ev) != 2 {
		t.Fatalf("want 2 new, got %v", k)
	}

	// Undelivered events stay pending.
	if ev2, _ := s.Pending(day0, 0); len(ev2) != 2 {
		t.Fatalf("events lost without MarkDelivered: %d", len(ev2))
	}
	if err := s.MarkDelivered(ev, day0); err != nil {
		t.Fatal(err)
	}
	if ev, _ = s.Pending(day0.AddDate(0, 0, 6), 7*24*time.Hour); len(ev) != 0 {
		t.Fatalf("want nothing pending, got %+v", ev)
	}

	ev, _ = s.Pending(day0.AddDate(0, 0, 8), 7*24*time.Hour)
	if len(ev) != 1 || ev[0].Kind != StillOpen || ev[0].AdvisoryID != "CVE-1" || ev[0].DaysOpen != 8 {
		t.Fatalf("want critical reminder only, got %+v", ev)
	}
	if ev, _ = s.Pending(day0.AddDate(0, 0, 8), 0); len(ev) != 0 {
		t.Fatalf("reminders without --renotify: %+v", ev)
	}

	doSync(t, s, Run{Now: day0.AddDate(0, 0, 9), Findings: []Finding{med}, Scanned: sc})
	doSync(t, s, Run{Now: day0.AddDate(0, 0, 10), Findings: []Finding{med}, Scanned: sc})
	ev, _ = s.Pending(day0.AddDate(0, 0, 10), 0)
	if len(ev) != 1 || ev[0].Kind != Fixed {
		t.Fatalf("want fixed event, got %+v", ev)
	}
	if err := s.MarkDelivered(ev, day0.AddDate(0, 0, 10)); err != nil {
		t.Fatal(err)
	}
	if ev, _ = s.Pending(day0.AddDate(0, 0, 10), 0); len(ev) != 0 {
		t.Fatalf("fixed event repeated: %+v", ev)
	}
}

func TestOpenUnwritable(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(blocker, "state.db")); err == nil {
		t.Fatal("want error for a path below a regular file")
	}
}
