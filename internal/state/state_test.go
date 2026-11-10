package state

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TadeasDitte/Svetovit/internal/rozhanitsy"
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
	return Finding{Location: loc, Component: "plugin", Version: "1.0", AdvisoryID: cve, Severity: severity, Score: new(9.0), Scope: Apps}
}

func doSync(t *testing.T, s *Store, run Run) *Changes {
	t.Helper()
	c, err := s.Sync(run)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// scanned marks locations as looked at with nothing installed there any more: what was found before is gone.
func scanned(locs ...string) Inventory {
	inv := make(Inventory)
	for _, l := range locs {
		inv[l] = map[string][]string{}
	}
	return inv
}

// installedAt marks a location as looked at with finding()'s component still present at the given versions.
func installedAt(loc string, versions ...string) Inventory {
	inv := scanned(loc)
	for _, v := range versions {
		inv.Add(loc, "plugin", v)
	}
	return inv
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

	onlyCritical := func(severity string, _ *float64) bool { return severity == "CRITICAL" }
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
	if err := s.MarkDelivered("all", nil, day0); err != nil {
		t.Fatal(err)
	}
	doSync(t, s, Run{Now: day0, Findings: []Finding{crit, med}, Scanned: sc})

	ev, err := s.Pending("all", "", day0, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(ev); k[New] != 2 || len(ev) != 2 {
		t.Fatalf("want 2 new, got %v", k)
	}

	// Undelivered events stay pending.
	if ev2, _ := s.Pending("all", "", day0, 0); len(ev2) != 2 {
		t.Fatalf("events lost without MarkDelivered: %d", len(ev2))
	}
	if err := s.MarkDelivered("all", ev, day0); err != nil {
		t.Fatal(err)
	}
	if ev, _ = s.Pending("all", "", day0.AddDate(0, 0, 6), 7*24*time.Hour); len(ev) != 0 {
		t.Fatalf("want nothing pending, got %+v", ev)
	}

	ev, _ = s.Pending("all", "", day0.AddDate(0, 0, 8), 7*24*time.Hour)
	if len(ev) != 1 || ev[0].Kind != StillOpen || ev[0].AdvisoryID != "CVE-1" || ev[0].DaysOpen != 8 {
		t.Fatalf("want critical reminder only, got %+v", ev)
	}
	if ev, _ = s.Pending("all", "", day0.AddDate(0, 0, 8), 0); len(ev) != 0 {
		t.Fatalf("reminders without --renotify: %+v", ev)
	}

	doSync(t, s, Run{Now: day0.AddDate(0, 0, 9), Findings: []Finding{med}, Scanned: sc})
	doSync(t, s, Run{Now: day0.AddDate(0, 0, 10), Findings: []Finding{med}, Scanned: sc})
	ev, _ = s.Pending("all", "", day0.AddDate(0, 0, 10), 0)
	if len(ev) != 1 || ev[0].Kind != Fixed {
		t.Fatalf("want fixed event, got %+v", ev)
	}
	if err := s.MarkDelivered("all", ev, day0.AddDate(0, 0, 10)); err != nil {
		t.Fatal(err)
	}
	if ev, _ = s.Pending("all", "", day0.AddDate(0, 0, 10), 0); len(ev) != 0 {
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

func TestChannelsAreScopedAndIndependent(t *testing.T) {
	s := openTemp(t)
	for _, ch := range []string{"all", System, Apps} {
		if err := s.MarkDelivered(ch, nil, day0); err != nil {
			t.Fatal(err)
		}
	}
	app := finding("/www/a", "CVE-APP", "HIGH")
	pkg := finding("/var/lib/dpkg/status", "CVE-PKG", "HIGH")
	pkg.Scope = System
	doSync(t, s, Run{Now: day0, Findings: []Finding{app, pkg}, Scanned: scanned(app.Location, pkg.Location)})

	pending := func(channel, scope string) []Event {
		t.Helper()
		ev, err := s.Pending(channel, scope, day0, 0)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	if ev := pending(System, System); len(ev) != 1 || ev[0].AdvisoryID != "CVE-PKG" || ev[0].Kind != New {
		t.Fatalf("system channel: %+v", ev)
	}
	if ev := pending(Apps, Apps); len(ev) != 1 || ev[0].AdvisoryID != "CVE-APP" {
		t.Fatalf("apps channel: %+v", ev)
	}

	// The system webhook succeeds, the "all" webhook fails: only the system channel is marked.
	if err := s.MarkDelivered(System, pending(System, System), day0); err != nil {
		t.Fatal(err)
	}
	if ev := pending(System, System); len(ev) != 0 {
		t.Fatalf("system channel repeated: %+v", ev)
	}
	if ev := pending("all", ""); len(ev) != 2 {
		t.Fatalf("all channel lost events another channel delivered: %+v", ev)
	}

	// Resolutions only go to channels that announced the finding.
	doSync(t, s, Run{Now: day0, Scanned: scanned(app.Location, pkg.Location)})
	doSync(t, s, Run{Now: day0, Scanned: scanned(app.Location, pkg.Location)})
	if ev := pending(System, System); len(ev) != 1 || ev[0].Kind != Fixed {
		t.Fatalf("system channel resolution: %+v", ev)
	}
	if ev := pending("all", ""); len(ev) != 0 {
		t.Fatalf("all channel told about fixes it never announced: %+v", ev)
	}
	if err := s.MarkDelivered(System, pending(System, System), day0); err != nil {
		t.Fatal(err)
	}

	// A finding that comes back is announced again on every channel.
	doSync(t, s, Run{Now: day0, Findings: []Finding{pkg}, Scanned: scanned(pkg.Location)})
	if ev := pending(System, System); len(ev) != 1 || ev[0].Kind != New {
		t.Fatalf("reopened finding on system channel: %+v", ev)
	}
}

func TestNewChannelGetsBaseline(t *testing.T) {
	s := openTemp(t)
	doSync(t, s, Run{Now: day0, Findings: []Finding{finding("/www/a", "CVE-1", "HIGH")}, Scanned: scanned("/www/a")})

	ev, err := s.Pending("all", "", day0.AddDate(0, 0, 30), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Kind != Current || ev[0].DaysOpen != 30 {
		t.Fatalf("want baseline, got %+v", ev)
	}
	if err := s.MarkDelivered("all", ev, day0.AddDate(0, 0, 30)); err != nil {
		t.Fatal(err)
	}

	doSync(t, s, Run{Now: day0, Findings: []Finding{finding("/www/a", "CVE-1", "HIGH"), finding("/www/a", "CVE-2", "HIGH")}, Scanned: scanned("/www/a")})
	if ev, _ = s.Pending("all", "", day0.AddDate(0, 0, 31), 0); len(ev) != 1 || ev[0].Kind != New || ev[0].AdvisoryID != "CVE-2" {
		t.Fatalf("want one new after baseline, got %+v", ev)
	}
}

func TestOpenRewritesDoubledVendorNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{
		"squizlabs/squizlabs/php_codesniffer", "@babel/@babel/core", "acme/tool", "plain",
		"phpunit/phpunit/phpunit", "phpunit/phpunit",
	} {
		if _, err := s.db.Exec(`INSERT INTO findings (location, component, version, advisory_id, scope, first_seen, last_seen) VALUES ('/a', ?, '1', 'CVE-1', 'apps', 1, 1)`, c); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO deliveries (channel, location, component, advisory_id, notified_at) VALUES ('all', '/a', ?, 'CVE-1', 1)`, c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	for range 2 {
		s, err = Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"findings", "deliveries"} {
			rows, err := s.db.Query(`SELECT component FROM ` + table + ` ORDER BY component`)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for rows.Next() {
				var c string
				rows.Scan(&c)
				got = append(got, c)
			}
			rows.Close()
			want := []string{"@babel/core", "acme/tool", "phpunit/phpunit", "plain", "squizlabs/php_codesniffer"}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s: got %v, want %v", table, got, want)
			}
		}
		s.Close()
	}
}

func TestUnknownScoreIsStoredAsNull(t *testing.T) {
	s := openTemp(t)
	f := finding("/www/a", "GHSA-1", "HIGH")
	f.Score = nil

	doSync(t, s, Run{Now: day0, Findings: []Finding{f}, Scanned: scanned("/www/a")})
	ev, err := s.Pending("all", "", day0, 0)
	if err != nil || len(ev) != 1 || ev[0].Score != nil {
		t.Fatalf("pending: %+v, %v", ev, err)
	}

	inScope := func(severity string, score *float64) bool { return rozhanitsy.MeetsMinScore(score, severity, 7) }
	for i := 1; i <= CleanRunsToResolve; i++ {
		c := doSync(t, s, Run{Now: day0.AddDate(0, 0, i), Scanned: scanned("/www/a"), InScope: inScope})
		if i == CleanRunsToResolve && len(c.Fixed) != 1 {
			t.Fatalf("run %d: %+v", i, c)
		}
	}
}

func TestOpenTurnsStoredZeroScoresIntoNull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, score := range []float64{0, 7.5} {
		if _, err := s.db.Exec(`INSERT INTO findings (location, component, version, advisory_id, score, scope, first_seen, last_seen) VALUES ('/a', 'c', '1', ?, ?, 'apps', 1, 1)`, fmt.Sprint(score), score); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var nulls, scored int
	if err := s.db.QueryRow(`SELECT COUNT(*) FILTER (WHERE score IS NULL), COUNT(*) FILTER (WHERE score = 7.5) FROM findings`).Scan(&nulls, &scored); err != nil {
		t.Fatal(err)
	}
	if nulls != 1 || scored != 1 {
		t.Errorf("got %d null and %d scored rows, want 1 and 1", nulls, scored)
	}
}

func TestWithdrawnWhenTheAPIStopsReportingAnUnchangedInstall(t *testing.T) {
	s := openTemp(t)
	f := finding("/www/a", "CVE-1", "HIGH")
	inv := installedAt("/www/a", "1.0")
	if err := s.MarkDelivered("all", nil, day0); err != nil {
		t.Fatal(err)
	}
	doSync(t, s, Run{Now: day0, Findings: []Finding{f}, Scanned: inv})
	ev, _ := s.Pending("all", "", day0, 0)
	if err := s.MarkDelivered("all", ev, day0); err != nil {
		t.Fatal(err)
	}

	// The advisory is absent from the response although plugin 1.0 is still installed.
	c := doSync(t, s, Run{Now: day0.AddDate(0, 0, 1), Scanned: inv})
	if len(c.Fixed)+len(c.Withdrawn) != 0 {
		t.Fatalf("resolved after one run: %+v", c)
	}
	c = doSync(t, s, Run{Now: day0.AddDate(0, 0, 2), Scanned: inv})
	if len(c.Fixed) != 0 || len(c.Withdrawn) != 1 || c.Withdrawn[0].DaysOpen != 2 {
		t.Fatalf("want one withdrawn, no fixed: %+v", c)
	}
	if ev, _ = s.Pending("all", "", day0.AddDate(0, 0, 2), 0); len(ev) != 1 || ev[0].Kind != Withdrawn {
		t.Fatalf("want a withdrawn notification: %+v", ev)
	}
	if err := s.MarkDelivered("all", ev, day0.AddDate(0, 0, 2)); err != nil {
		t.Fatal(err)
	}

	// Returned by the API again: it carries on, with its age, and is not announced as new.
	c = doSync(t, s, Run{Now: day0.AddDate(0, 0, 3), Findings: []Finding{f}, Scanned: inv})
	if len(c.New) != 0 || c.Open != 1 {
		t.Fatalf("reported as new again: %+v", c)
	}
	if ev, _ = s.Pending("all", "", day0.AddDate(0, 0, 3), 0); len(ev) != 0 {
		t.Fatalf("notified again: %+v", ev)
	}

	// Once the install really changes, it is fixed, counting from the original first_seen.
	doSync(t, s, Run{Now: day0.AddDate(0, 0, 4), Scanned: scanned("/www/a")})
	c = doSync(t, s, Run{Now: day0.AddDate(0, 0, 5), Scanned: scanned("/www/a")})
	if len(c.Fixed) != 1 || c.Fixed[0].DaysOpen != 5 {
		t.Fatalf("want fixed after 5 days: %+v", c)
	}
	if ev, _ = s.Pending("all", "", day0.AddDate(0, 0, 5), 0); len(ev) != 1 || ev[0].Kind != Fixed {
		t.Fatalf("want a fixed notification: %+v", ev)
	}
}

func TestStillApplicableAdvisorySurvivesAVersionUpdate(t *testing.T) {
	s := openTemp(t)
	old := finding("/www/a", "CVE-1", "MEDIUM")
	updated := old
	updated.Version = "1.1"

	doSync(t, s, Run{Now: day0, Findings: []Finding{old}, Scanned: installedAt("/www/a", "1.0")})
	c := doSync(t, s, Run{Now: day0.AddDate(0, 0, 26), Findings: []Finding{updated}, Scanned: installedAt("/www/a", "1.1")})
	if len(c.New) != 0 || len(c.Fixed) != 0 || c.Open != 1 {
		t.Fatalf("version bump reported as fixed and new: %+v", c)
	}

	ev, err := s.Pending("all", "", day0.AddDate(0, 0, 26), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Kind != Current || ev[0].Version != "1.1" || ev[0].DaysOpen != 26 {
		t.Fatalf("want one 26-day-old finding at the new version: %+v", ev)
	}

	// The old version is gone and the advisory no longer applies: now it is fixed, with its full age.
	doSync(t, s, Run{Now: day0.AddDate(0, 0, 27), Scanned: installedAt("/www/a", "1.2")})
	c = doSync(t, s, Run{Now: day0.AddDate(0, 0, 28), Scanned: installedAt("/www/a", "1.2")})
	if len(c.Fixed) != 1 || c.Fixed[0].DaysOpen != 28 || c.Fixed[0].Version != "1.1" {
		t.Fatalf("want fixed after 28 days: %+v", c)
	}
}

func TestSeveralInstalledVersionsShareOneFinding(t *testing.T) {
	s := openTemp(t)
	a := finding("/www/lock", "CVE-1", "HIGH")
	b := a
	b.Version = "2.0"
	inv := installedAt("/www/lock", "1.0", "2.0")

	c := doSync(t, s, Run{Now: day0, Findings: []Finding{b, a}, Scanned: inv})
	if len(c.New) != 1 || c.New[0].Version != "1.0, 2.0" || c.Open != 1 {
		t.Fatalf("want one finding naming both versions: %+v", c)
	}

	// Only 2.0 is left; the advisory still applies, so nothing is resolved.
	c = doSync(t, s, Run{Now: day0.AddDate(0, 0, 1), Findings: []Finding{b}, Scanned: installedAt("/www/lock", "2.0")})
	if len(c.New)+len(c.Fixed) != 0 || c.Open != 1 {
		t.Fatalf("dropping one version changed the finding: %+v", c)
	}
	ev, _ := s.Pending("all", "", day0.AddDate(0, 0, 1), 0)
	if len(ev) != 1 || ev[0].Version != "2.0" {
		t.Fatalf("want the version it is still installed at: %+v", ev)
	}
}

const oldSchema = `
CREATE TABLE findings (
  location TEXT NOT NULL, component TEXT NOT NULL, version TEXT NOT NULL, advisory_id TEXT NOT NULL,
  severity TEXT, score REAL, fixed_in TEXT, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  scope TEXT NOT NULL, clean_runs INTEGER NOT NULL DEFAULT 0, resolved_at INTEGER, resolution TEXT,
  PRIMARY KEY (location, component, version, advisory_id));
CREATE TABLE channels (name TEXT PRIMARY KEY, since INTEGER NOT NULL);
CREATE TABLE deliveries (
  channel TEXT NOT NULL, location TEXT NOT NULL, component TEXT NOT NULL, version TEXT NOT NULL,
  advisory_id TEXT NOT NULL, notified_at INTEGER NOT NULL, resolve_notified INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (channel, location, component, version, advisory_id));
PRAGMA user_version = 2;
`

func TestOpenRekeysFindingsOnInstallNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		location, component, version, advisory, scope string
		firstSeen, lastSeen                           int64
		resolvedAt                                    any
		resolution                                    string
	}{
		// One install, two vendor names, the same advisory: one finding, aged from the older row.
		{"/www/a/wp-content/plugins/forminator", "wpmudev/forminator", "1.38.1", "CVE-1", "apps", 100, 300, nil, ""},
		{"/www/a/wp-content/plugins/forminator", "incsub/forminator", "1.38.1", "CVE-1", "apps", 200, 300, nil, ""},
		// A version bump: the old row was resolved as fixed, the new one reopened. One finding, aged from the first.
		{"/www/b/web", "wordpress", "5.8.18", "CVE-2", "apps", 100, 200, int64(200), string(Fixed)},
		{"/www/b/web", "wordpress", "5.8.19", "CVE-2", "apps", 250, 300, nil, ""},
		// Composer and npm names keep their namespace; the vendor of a matched range is dropped.
		{"/www/c/composer.lock", "acme/squizlabs/php_codesniffer", "2.9.2", "GHSA-1", "apps", 100, 300, nil, ""},
		{"/www/c/pnpm-lock.yaml", "babel/@babel/core", "7.0.0", "GHSA-2", "apps", 100, 300, nil, ""},
		{"/www/c/pnpm-lock.yaml", "haxx/lodash", "4.0.0", "GHSA-3", "apps", 100, 300, nil, ""},
		// OS packages are named after the package; a nix install keeps its nixpkgs vendor.
		{"/var/lib/dpkg/status", "rocky-linux/nginx", "1.24", "CVE-3", "system", 100, 300, nil, ""},
		{nixSource, "nginx/nginx", "1.24", "CVE-4", "system", 100, 300, nil, ""},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO findings (location, component, version, advisory_id, severity, score, scope,
			first_seen, last_seen, clean_runs, resolved_at, resolution) VALUES (?, ?, ?, ?, 'HIGH', 7.5, ?, ?, ?, 1, ?, ?)`,
			r.location, r.component, r.version, r.advisory, r.scope, r.firstSeen, r.lastSeen, r.resolvedAt, nullString(r.resolution)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO deliveries (channel, location, component, version, advisory_id, notified_at, resolve_notified)
			VALUES ('all', ?, ?, ?, ?, ?, 1)`, r.location, r.component, r.version, r.advisory, r.lastSeen); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got, err := query(s.db, ``)
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		component, version string
		firstSeen          int64
		open               bool
	}
	wants := map[string]want{
		"/www/a/wp-content/plugins/forminator CVE-1": {"forminator", "1.38.1", 100, true},
		"/www/b/web CVE-2":                           {"wordpress", "5.8.19", 100, true},
		"/www/c/composer.lock GHSA-1":                {"squizlabs/php_codesniffer", "2.9.2", 100, true},
		"/www/c/pnpm-lock.yaml GHSA-2":               {"@babel/core", "7.0.0", 100, true},
		"/www/c/pnpm-lock.yaml GHSA-3":               {"lodash", "4.0.0", 100, true},
		"/var/lib/dpkg/status CVE-3":                 {"nginx", "1.24", 100, true},
		nixSource + " CVE-4":                         {"nginx/nginx", "1.24", 100, true},
	}
	if len(got) != len(wants) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(wants), got)
	}
	for _, f := range got {
		w, ok := wants[f.Location+" "+f.AdvisoryID]
		if !ok {
			t.Errorf("unexpected finding %+v", f.Finding)
			continue
		}
		if f.Component != w.component || f.Version != w.version || f.firstSeen.Unix() != w.firstSeen {
			t.Errorf("%s %s: got %s %s first_seen %d, want %s %s %d",
				f.Location, f.AdvisoryID, f.Component, f.Version, f.firstSeen.Unix(), w.component, w.version, w.firstSeen)
		}
		if w.open && f.resolution != "" {
			t.Errorf("%s %s: resolved as %s although it is still reported", f.Location, f.AdvisoryID, f.resolution)
		}
	}

	var deliveries int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM deliveries`).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != len(wants) {
		t.Errorf("got %d deliveries, want %d", deliveries, len(wants))
	}

	// The merged findings are the ones a scan now reports: nothing is announced as new or fixed.
	inv := make(Inventory)
	for _, f := range got {
		inv.Add(f.Location, f.Component, f.Version)
	}
	var findings []Finding
	for _, f := range got {
		findings = append(findings, f.Finding)
	}
	c := doSync(t, s, Run{Now: time.Unix(400, 0), Findings: findings, Scanned: inv})
	if len(c.New)+len(c.Fixed)+len(c.Withdrawn) != 0 || c.Open != len(wants) {
		t.Fatalf("the migrated findings were not recognised: %+v", c)
	}
}
