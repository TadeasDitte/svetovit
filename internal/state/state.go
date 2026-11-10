package state

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const CleanRunsToResolve = 2

const schema = `
CREATE TABLE IF NOT EXISTS findings (
  location         TEXT NOT NULL,
  component        TEXT NOT NULL,
  version          TEXT NOT NULL,
  advisory_id      TEXT NOT NULL,
  severity         TEXT,
  score            REAL,
  fixed_in         TEXT,
  first_seen       INTEGER NOT NULL,
  last_seen        INTEGER NOT NULL,
  scope            TEXT NOT NULL,
  clean_runs       INTEGER NOT NULL DEFAULT 0,
  resolved_at      INTEGER,
  resolution       TEXT,
  PRIMARY KEY (location, component, advisory_id)
);
CREATE INDEX IF NOT EXISTS findings_open ON findings (resolved_at);
CREATE TABLE IF NOT EXISTS channels (
  name  TEXT PRIMARY KEY,
  since INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
  channel          TEXT NOT NULL,
  location         TEXT NOT NULL,
  component        TEXT NOT NULL,
  advisory_id      TEXT NOT NULL,
  notified_at      INTEGER NOT NULL,
  resolve_notified INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (channel, location, component, advisory_id)
);
`

type Finding struct {
	Location   string   `json:"location"`
	Component  string   `json:"component"`
	Version    string   `json:"version"` // several installed versions affected at one location are joined with ", "
	AdvisoryID string   `json:"advisory_id"`
	Severity   string   `json:"severity"`
	Score      *float64 `json:"score"`
	FixedIn    string   `json:"fixed_in,omitempty"`
	Scope      string   `json:"scope"`
}

type Kind string

const (
	System = "system"
	Apps   = "apps"
)

const (
	New       Kind = "new"
	Fixed     Kind = "fixed"
	Removed   Kind = "removed"
	Withdrawn Kind = "withdrawn"
	StillOpen Kind = "still_open"
	Current   Kind = "current"
)

func (k Kind) resolves() bool { return k == Fixed || k == Removed || k == Withdrawn }

type Event struct {
	Kind Kind `json:"type"`
	Finding
	FirstSeen time.Time `json:"first_seen,omitzero"`
	DaysOpen  int       `json:"days_open"`
}

type Changes struct {
	New        []Event   `json:"new"`
	Fixed      []Event   `json:"fixed"`
	Removed    []Event   `json:"removed"`
	Withdrawn  []Event   `json:"withdrawn"`
	Open       int       `json:"open"`
	OldestOpen time.Time `json:"oldest_open,omitzero"`
}

// Inventory holds the locations scanned in a run and, for each, the installed versions of every component found there.
type Inventory map[string]map[string][]string

func (inv Inventory) Add(location, component, version string) {
	if inv[location] == nil {
		inv[location] = make(map[string][]string)
	}
	if !slices.Contains(inv[location][component], version) {
		inv[location][component] = append(inv[location][component], version)
	}
}

type Run struct {
	Now        time.Time
	Findings   []Finding
	Scanned    Inventory
	TargetRoot string
	InScope    func(severity string, score *float64) bool
}

type Store struct {
	db   *sql.DB
	path string
}

func DefaultPath() string {
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			return filepath.Join(dir, "svetovit", "state.db")
		}
	} else if os.Geteuid() == 0 {
		return "/var/lib/svetovit/state.db"
	}
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "svetovit", "state.db")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "svetovit", "state.db")
	}
	return "svetovit-state.db"
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, notWritable(path, err)
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, notWritable(path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, notWritable(path, err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("state database %s: migrating: %w", path, err)
	}
	return &Store{db: db, path: path}, nil
}

var migrations = []func(tx *sql.Tx) error{
	func(tx *sql.Tx) error {
		for _, table := range []string{"findings", "deliveries"} {
			if _, err := tx.Exec(`UPDATE OR IGNORE ` + table + ` SET component = substr(component, instr(component, '/') + 1)
				WHERE instr(component, '/') > 0
				AND substr(component, instr(component, '/') + 1, instr(component, '/')) = substr(component, 1, instr(component, '/'))`); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM ` + table + `
				WHERE instr(component, '/') > 0
				AND substr(component, instr(component, '/') + 1, instr(component, '/')) = substr(component, 1, instr(component, '/'))`); err != nil {
				return err
			}
		}
		return nil
	},
	func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE findings SET score = NULL WHERE score = 0`)
		return err
	},
	rekey,
}

func migrate(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var version int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version >= len(migrations) {
		return nil
	}
	for _, step := range migrations[version:] {
		if err := step(tx); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations))); err != nil {
		return err
	}
	return tx.Commit()
}

func notWritable(path string, err error) error {
	return fmt.Errorf("state database %s is not writable: %w; pass --state=<path> to put it elsewhere", path, err)
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Sync(run Run) (*Changes, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	defer tx.Rollback()

	changes, err := sync(tx, run)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	return changes, nil
}

type key struct{ location, component, advisory string }

func (f Finding) key() key { return key{f.Location, f.Component, f.AdvisoryID} }

const versionSep = ", "

func addVersion(list, version string) string {
	versions := strings.Split(list, versionSep)
	if slices.Contains(versions, version) {
		return list
	}
	versions = append(versions, version)
	slices.Sort(versions)
	return strings.Join(versions, versionSep)
}

func stillInstalled(versions string, installed []string) bool {
	for _, v := range strings.Split(versions, versionSep) {
		if slices.Contains(installed, v) {
			return true
		}
	}
	return false
}

func updateFinding(tx *sql.Tx, f *Finding, set string, args ...any) error {
	args = append([]any{f.Version, f.Severity, f.Score, f.FixedIn, f.Scope}, args...)
	_, err := tx.Exec(`UPDATE findings SET version = ?, severity = ?, score = ?, fixed_in = ?, scope = ?, `+set+`
		WHERE location = ? AND component = ? AND advisory_id = ?`, append(args, f.Location, f.Component, f.AdvisoryID)...)
	return err
}

func sync(tx *sql.Tx, run Run) (*Changes, error) {
	now := run.Now.Unix()
	changes := &Changes{New: []Event{}, Fixed: []Event{}, Removed: []Event{}, Withdrawn: []Event{}}
	seen := make(map[key]*Finding, len(run.Findings))
	var found []*Finding

	for _, f := range run.Findings {
		if prev := seen[f.key()]; prev != nil {
			prev.Version = addVersion(prev.Version, f.Version)
			continue
		}
		seen[f.key()] = &f
		found = append(found, &f)
	}

	for _, f := range found {
		var resolved sql.NullInt64
		var resolution sql.NullString
		err := tx.QueryRow(`SELECT resolved_at, resolution FROM findings WHERE location = ? AND component = ? AND advisory_id = ?`,
			f.Location, f.Component, f.AdvisoryID).Scan(&resolved, &resolution)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.Exec(`INSERT INTO findings (location, component, version, advisory_id, severity, score, fixed_in, scope, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				f.Location, f.Component, f.Version, f.AdvisoryID, f.Severity, f.Score, f.FixedIn, f.Scope, now, now)
			changes.New = append(changes.New, Event{Kind: New, Finding: *f, FirstSeen: run.Now})
		case err != nil:
			return nil, err
		case !resolved.Valid:
			err = updateFinding(tx, f, `last_seen = ?, clean_runs = 0`, now)
		case Kind(resolution.String) == Withdrawn:
			// Reported again for an install that did not change: it carries on, without being announced again.
			err = updateFinding(tx, f, `last_seen = ?, clean_runs = 0, resolved_at = NULL, resolution = NULL`, now)
			if err == nil {
				_, err = tx.Exec(`UPDATE deliveries SET resolve_notified = 0 WHERE location = ? AND component = ? AND advisory_id = ?`,
					f.Location, f.Component, f.AdvisoryID)
			}
		default:
			// Back after being fixed or removed (a restored backup, a downgrade): announce it again, counting from now.
			err = updateFinding(tx, f, `first_seen = ?, last_seen = ?, clean_runs = 0, resolved_at = NULL, resolution = NULL`, now, now)
			if err == nil {
				_, err = tx.Exec(`DELETE FROM deliveries WHERE location = ? AND component = ? AND advisory_id = ?`,
					f.Location, f.Component, f.AdvisoryID)
			}
			changes.New = append(changes.New, Event{Kind: New, Finding: *f, FirstSeen: run.Now})
		}
		if err != nil {
			return nil, err
		}
	}

	open, err := openFindings(tx)
	if err != nil {
		return nil, err
	}
	for _, o := range open {
		if seen[o.key()] != nil {
			continue
		}
		if run.InScope != nil && !run.InScope(o.Severity, o.Score) {
			continue
		}
		var resolution Kind
		installed, scanned := run.Scanned[o.Location]
		switch {
		case scanned && stillInstalled(o.Version, installed[o.Component]):
			resolution = Withdrawn
		case scanned:
			resolution = Fixed
		case under(o.Location, run.TargetRoot) && gone(o.Location):
			resolution = Removed
		default:
			continue
		}
		if o.cleanRuns+1 < CleanRunsToResolve {
			if _, err := tx.Exec(`UPDATE findings SET clean_runs = clean_runs + 1
				WHERE location = ? AND component = ? AND advisory_id = ?`,
				o.Location, o.Component, o.AdvisoryID); err != nil {
				return nil, err
			}
			continue
		}
		if _, err := tx.Exec(`UPDATE findings SET clean_runs = clean_runs + 1, resolved_at = ?, resolution = ?
			WHERE location = ? AND component = ? AND advisory_id = ?`,
			now, string(resolution), o.Location, o.Component, o.AdvisoryID); err != nil {
			return nil, err
		}
		ev := Event{Kind: resolution, Finding: o.Finding, FirstSeen: o.firstSeen, DaysOpen: days(o.firstSeen, run.Now)}
		switch resolution {
		case Fixed:
			changes.Fixed = append(changes.Fixed, ev)
		case Removed:
			changes.Removed = append(changes.Removed, ev)
		case Withdrawn:
			changes.Withdrawn = append(changes.Withdrawn, ev)
		}
	}

	var oldest sql.NullInt64
	if err := tx.QueryRow(`SELECT COUNT(*), MIN(first_seen) FROM findings WHERE resolved_at IS NULL`).Scan(&changes.Open, &oldest); err != nil {
		return nil, err
	}
	if oldest.Valid {
		changes.OldestOpen = time.Unix(oldest.Int64, 0)
	}
	return changes, nil
}

type stored struct {
	Finding
	firstSeen  time.Time
	cleanRuns  int
	resolution string
}

const storedColumns = `f.location, f.component, f.version, f.advisory_id, COALESCE(f.severity, ''), f.score,
	COALESCE(f.fixed_in, ''), f.scope, f.first_seen, f.clean_runs, COALESCE(f.resolution, '')`

func query(q interface {
	Query(string, ...any) (*sql.Rows, error)
}, rest string, args ...any) ([]stored, error) {
	rows, err := q.Query(`SELECT `+storedColumns+` FROM findings f `+rest+` ORDER BY f.location, f.component, f.advisory_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []stored
	for rows.Next() {
		var s stored
		var first int64
		if err := rows.Scan(&s.Location, &s.Component, &s.Version, &s.AdvisoryID, &s.Severity, &s.Score, &s.FixedIn,
			&s.Scope, &first, &s.cleanRuns, &s.resolution); err != nil {
			return nil, err
		}
		s.firstSeen = time.Unix(first, 0)
		out = append(out, s)
	}
	return out, rows.Err()
}

func openFindings(tx *sql.Tx) ([]stored, error) {
	return query(tx, `WHERE f.resolved_at IS NULL`)
}

const deliveryJoin = `LEFT JOIN deliveries d ON d.channel = ? AND d.location = f.location AND d.component = f.component
	AND d.advisory_id = f.advisory_id `

func (s *Store) Pending(channel, scope string, now time.Time, renotify time.Duration) ([]Event, error) {
	pick := func(where string, extra ...any) ([]stored, error) {
		args := append([]any{channel}, extra...)
		if scope != "" {
			where += ` AND f.scope = ?`
			args = append(args, scope)
		}
		rows, err := query(s.db, deliveryJoin+where, args...)
		if err != nil {
			return nil, fmt.Errorf("state: %w", err)
		}
		return rows, nil
	}
	var events []Event
	add := func(kind Kind, rows []stored) {
		for _, f := range rows {
			k := kind
			if k == "" {
				k = Kind(f.resolution)
			}
			events = append(events, Event{Kind: k, Finding: f.Finding, FirstSeen: f.firstSeen, DaysOpen: days(f.firstSeen, now)})
		}
	}

	var known bool
	if err := s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM channels WHERE name = ?)`, channel).Scan(&known); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	fresh, err := pick(`WHERE f.resolved_at IS NULL AND d.channel IS NULL`)
	if err != nil {
		return nil, err
	}
	if !known {
		add(Current, fresh)
		return events, nil
	}
	add(New, fresh)

	resolved, err := pick(`WHERE f.resolved_at IS NOT NULL AND d.channel IS NOT NULL AND d.resolve_notified = 0`)
	if err != nil {
		return nil, err
	}
	add("", resolved)

	if renotify > 0 {
		due, err := pick(`WHERE f.resolved_at IS NULL AND d.notified_at <= ? AND UPPER(f.severity) IN ('CRITICAL', 'HIGH')`,
			now.Add(-renotify).Unix())
		if err != nil {
			return nil, err
		}
		add(StillOpen, due)
	}
	return events, nil
}

func (s *Store) MarkDelivered(channel string, events []Event, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`INSERT OR IGNORE INTO channels (name, since) VALUES (?, ?)`, channel, now.Unix()); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	for _, ev := range events {
		if ev.Kind.resolves() {
			_, err = tx.Exec(`UPDATE deliveries SET resolve_notified = 1
				WHERE channel = ? AND location = ? AND component = ? AND advisory_id = ?`,
				channel, ev.Location, ev.Component, ev.AdvisoryID)
		} else {
			_, err = tx.Exec(`INSERT INTO deliveries (channel, location, component, advisory_id, notified_at)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT (channel, location, component, advisory_id) DO UPDATE SET notified_at = excluded.notified_at`,
				channel, ev.Location, ev.Component, ev.AdvisoryID, now.Unix())
		}
		if err != nil {
			return fmt.Errorf("state: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	return nil
}

func under(path, root string) bool {
	if root == "" {
		return false
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func gone(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, fs.ErrNotExist)
}

func days(from, to time.Time) int {
	if from.IsZero() || to.Before(from) {
		return 0
	}
	return int(to.Sub(from).Hours() / 24)
}

// nixSource is where nix system packages are recorded; their component names were refined to an exact nixpkgs
// vendor/product, so rekey leaves them alone.
const nixSource = "/run/current-system"

// rekey rebuilds both tables for the current primary keys: findings are keyed by location, component and advisory,
// without the version, and components are named after the install rather than the vendor of whichever advisory range
// matched. Rows that now share a key are merged, keeping the earliest first_seen, so a finding's age survives.
func rekey(tx *sql.Tx) error {
	outdated, err := hasColumn(tx, "deliveries", "version")
	if err != nil || !outdated {
		return err
	}

	type merged struct {
		stored
		lastSeen   int64
		resolvedAt sql.NullInt64
		notifiedAt int64
		resolveNot int
	}
	findings := map[key]*merged{}
	var order []key

	rows, err := tx.Query(`SELECT location, component, version, advisory_id, COALESCE(severity, ''), score,
		COALESCE(fixed_in, ''), scope, first_seen, last_seen, clean_runs, resolved_at, COALESCE(resolution, '')
		FROM findings ORDER BY last_seen, first_seen`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var m merged
		var first int64
		if err := rows.Scan(&m.Location, &m.Component, &m.Version, &m.AdvisoryID, &m.Severity, &m.Score, &m.FixedIn,
			&m.Scope, &first, &m.lastSeen, &m.cleanRuns, &m.resolvedAt, &m.resolution); err != nil {
			rows.Close()
			return err
		}
		m.firstSeen = time.Unix(first, 0)
		m.Component = rename(m.Location, m.Component)
		k := m.Finding.key()
		prev, ok := findings[k]
		if !ok {
			findings[k] = &m
			order = append(order, k)
			continue
		}
		// Rows arrive oldest-seen first, so the later one describes the install as it is now; the age is the oldest,
		// which gives back what a version bump or a second vendor name had reset.
		if prev.firstSeen.Before(m.firstSeen) {
			m.firstSeen = prev.firstSeen
		}
		m.cleanRuns = min(m.cleanRuns, prev.cleanRuns)
		if !prev.resolvedAt.Valid {
			m.resolvedAt, m.resolution = sql.NullInt64{}, ""
		}
		findings[k] = &m
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	type deliveryKey struct {
		channel string
		key
	}
	deliveries := map[deliveryKey]*merged{}
	var deliveryOrder []deliveryKey
	rows, err = tx.Query(`SELECT channel, location, component, advisory_id, notified_at, resolve_notified FROM deliveries`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var d merged
		var channel string
		if err := rows.Scan(&channel, &d.Location, &d.Component, &d.AdvisoryID, &d.notifiedAt, &d.resolveNot); err != nil {
			rows.Close()
			return err
		}
		d.Component = rename(d.Location, d.Component)
		k := deliveryKey{channel, d.Finding.key()}
		if prev, ok := deliveries[k]; ok {
			d.notifiedAt = max(d.notifiedAt, prev.notifiedAt)
			d.resolveNot = min(d.resolveNot, prev.resolveNot)
		} else {
			deliveryOrder = append(deliveryOrder, k)
		}
		deliveries[k] = &d
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, stmt := range []string{`DROP TABLE findings`, `DROP TABLE deliveries`, schema} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	for _, k := range order {
		f := findings[k]
		if _, err := tx.Exec(`INSERT INTO findings (location, component, version, advisory_id, severity, score, fixed_in,
			scope, first_seen, last_seen, clean_runs, resolved_at, resolution)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.Location, f.Component, f.Version, f.AdvisoryID, f.Severity, f.Score, f.FixedIn, f.Scope,
			f.firstSeen.Unix(), f.lastSeen, f.cleanRuns, f.resolvedAt, nullString(f.resolution)); err != nil {
			return err
		}
	}
	for _, k := range deliveryOrder {
		d := deliveries[k]
		if _, err := tx.Exec(`INSERT INTO deliveries (channel, location, component, advisory_id, notified_at, resolve_notified)
			VALUES (?, ?, ?, ?, ?, ?)`, k.channel, d.Location, d.Component, d.AdvisoryID, d.notifiedAt, d.resolveNot); err != nil {
			return err
		}
	}
	return nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func hasColumn(tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.Query(`SELECT 1 FROM pragma_table_info(?) WHERE name = ?`, table, column)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	return rows.Next(), rows.Err()
}

// rename maps a stored component name to the name the install is tracked under now.
func rename(location, component string) string {
	if location == nixSource {
		return component
	}
	switch filepath.Base(location) {
	case "composer.lock":
		// A Composer package is always vendor/name; anything before that is the vendor of a matched range.
		return lastSegments(component, 2)
	case "pnpm-lock.yaml":
		// An npm name has a slash only when it is scoped (@scope/name).
		parts := strings.Split(component, "/")
		for i, p := range parts {
			if strings.HasPrefix(p, "@") {
				return strings.Join(parts[i:min(i+2, len(parts))], "/")
			}
		}
		return parts[len(parts)-1]
	}
	return lastSegment(component)
}

func lastSegment(component string) string { return lastSegments(component, 1) }

func lastSegments(component string, n int) string {
	parts := strings.Split(component, "/")
	if len(parts) <= n {
		return component
	}
	return strings.Join(parts[len(parts)-n:], "/")
}
