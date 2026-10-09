package state

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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
  PRIMARY KEY (location, component, version, advisory_id)
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
  version          TEXT NOT NULL,
  advisory_id      TEXT NOT NULL,
  notified_at      INTEGER NOT NULL,
  resolve_notified INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (channel, location, component, version, advisory_id)
);
`

type Finding struct {
	Location   string  `json:"location"`
	Component  string  `json:"component"`
	Version    string  `json:"version"`
	AdvisoryID string  `json:"advisory_id"`
	Severity   string  `json:"severity"`
	Score      float64 `json:"score"`
	FixedIn    string  `json:"fixed_in,omitempty"`
	Scope      string  `json:"scope"`
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
	StillOpen Kind = "still_open"
	Current   Kind = "current"
)

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
	Open       int       `json:"open"`
	OldestOpen time.Time `json:"oldest_open,omitzero"`
}

type Run struct {
	Now        time.Time
	Findings   []Finding
	Scanned    map[string]bool
	TargetRoot string
	InScope    func(severity string, score float64) bool
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
	return &Store{db: db, path: path}, nil
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

type key struct{ location, component, version, advisory string }

func (f Finding) key() key { return key{f.Location, f.Component, f.Version, f.AdvisoryID} }

func sync(tx *sql.Tx, run Run) (*Changes, error) {
	now := run.Now.Unix()
	changes := &Changes{New: []Event{}, Fixed: []Event{}, Removed: []Event{}}
	seen := make(map[key]bool, len(run.Findings))

	for _, f := range run.Findings {
		if seen[f.key()] {
			continue
		}
		seen[f.key()] = true

		var resolved sql.NullInt64
		err := tx.QueryRow(`SELECT resolved_at FROM findings WHERE location = ? AND component = ? AND version = ? AND advisory_id = ?`,
			f.Location, f.Component, f.Version, f.AdvisoryID).Scan(&resolved)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.Exec(`INSERT INTO findings (location, component, version, advisory_id, severity, score, fixed_in, scope, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				f.Location, f.Component, f.Version, f.AdvisoryID, f.Severity, f.Score, f.FixedIn, f.Scope, now, now)
			changes.New = append(changes.New, Event{Kind: New, Finding: f, FirstSeen: run.Now})
		case err != nil:
			return nil, err
		case resolved.Valid:
			// Back after being resolved (a restored backup, a downgrade): announce it again, counting from now.
			_, err = tx.Exec(`UPDATE findings SET severity = ?, score = ?, fixed_in = ?, scope = ?, first_seen = ?, last_seen = ?, clean_runs = 0,
				resolved_at = NULL, resolution = NULL
				WHERE location = ? AND component = ? AND version = ? AND advisory_id = ?`,
				f.Severity, f.Score, f.FixedIn, f.Scope, now, now, f.Location, f.Component, f.Version, f.AdvisoryID)
			if err == nil {
				_, err = tx.Exec(`DELETE FROM deliveries WHERE location = ? AND component = ? AND version = ? AND advisory_id = ?`,
					f.Location, f.Component, f.Version, f.AdvisoryID)
			}
			changes.New = append(changes.New, Event{Kind: New, Finding: f, FirstSeen: run.Now})
		default:
			_, err = tx.Exec(`UPDATE findings SET severity = ?, score = ?, fixed_in = ?, scope = ?, last_seen = ?, clean_runs = 0
				WHERE location = ? AND component = ? AND version = ? AND advisory_id = ?`,
				f.Severity, f.Score, f.FixedIn, f.Scope, now, f.Location, f.Component, f.Version, f.AdvisoryID)
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
		if seen[o.key()] {
			continue
		}
		if run.InScope != nil && !run.InScope(o.Severity, o.Score) {
			continue
		}
		var resolution Kind
		switch {
		case run.Scanned[o.Location]:
			resolution = Fixed
		case under(o.Location, run.TargetRoot) && gone(o.Location):
			resolution = Removed
		default:
			continue
		}
		if o.cleanRuns+1 < CleanRunsToResolve {
			if _, err := tx.Exec(`UPDATE findings SET clean_runs = clean_runs + 1
				WHERE location = ? AND component = ? AND version = ? AND advisory_id = ?`,
				o.Location, o.Component, o.Version, o.AdvisoryID); err != nil {
				return nil, err
			}
			continue
		}
		if _, err := tx.Exec(`UPDATE findings SET clean_runs = clean_runs + 1, resolved_at = ?, resolution = ?
			WHERE location = ? AND component = ? AND version = ? AND advisory_id = ?`,
			now, string(resolution), o.Location, o.Component, o.Version, o.AdvisoryID); err != nil {
			return nil, err
		}
		ev := Event{Kind: resolution, Finding: o.Finding, FirstSeen: o.firstSeen, DaysOpen: days(o.firstSeen, run.Now)}
		if resolution == Fixed {
			changes.Fixed = append(changes.Fixed, ev)
		} else {
			changes.Removed = append(changes.Removed, ev)
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

const storedColumns = `f.location, f.component, f.version, f.advisory_id, COALESCE(f.severity, ''), COALESCE(f.score, 0),
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
	AND d.version = f.version AND d.advisory_id = f.advisory_id `

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
		if ev.Kind == Fixed || ev.Kind == Removed {
			_, err = tx.Exec(`UPDATE deliveries SET resolve_notified = 1
				WHERE channel = ? AND location = ? AND component = ? AND version = ? AND advisory_id = ?`,
				channel, ev.Location, ev.Component, ev.Version, ev.AdvisoryID)
		} else {
			_, err = tx.Exec(`INSERT INTO deliveries (channel, location, component, version, advisory_id, notified_at)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (channel, location, component, version, advisory_id) DO UPDATE SET notified_at = excluded.notified_at`,
				channel, ev.Location, ev.Component, ev.Version, ev.AdvisoryID, now.Unix())
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
