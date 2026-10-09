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
  clean_runs       INTEGER NOT NULL DEFAULT 0,
  notified_at      INTEGER,
  resolved_at      INTEGER,
  resolution       TEXT,
  resolve_notified INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (location, component, version, advisory_id)
);
CREATE INDEX IF NOT EXISTS findings_open ON findings (resolved_at);
`

type Finding struct {
	Location   string  `json:"location"`
	Component  string  `json:"component"`
	Version    string  `json:"version"`
	AdvisoryID string  `json:"advisory_id"`
	Severity   string  `json:"severity"`
	Score      float64 `json:"score"`
	FixedIn    string  `json:"fixed_in,omitempty"`
}

type Kind string

const (
	New Kind = "new"
	Fixed Kind = "fixed"
	Removed Kind = "removed"
	StillOpen Kind = "still_open"
	Current Kind = "current"
)

type Event struct {
	Kind Kind `json:"type"`
	Finding
	FirstSeen time.Time `json:"first_seen,omitzero"`
	DaysOpen int `json:"days_open"`
}

type Changes struct {
	New        []Event   `json:"new"`
	Fixed      []Event   `json:"fixed"`
	Removed    []Event   `json:"removed"`
	Open       int       `json:"open"`
	OldestOpen time.Time `json:"oldest_open,omitzero"`
}

type Run struct {
	Now      time.Time
	Findings []Finding
	Scanned map[string]bool
	TargetRoot string
	InScope func(severity string, score float64) bool
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
			_, err = tx.Exec(`INSERT INTO findings (location, component, version, advisory_id, severity, score, fixed_in, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				f.Location, f.Component, f.Version, f.AdvisoryID, f.Severity, f.Score, f.FixedIn, now, now)
			changes.New = append(changes.New, Event{Kind: New, Finding: f, FirstSeen: run.Now})
		case err != nil:
			return nil, err
		case resolved.Valid:
			// Back after being resolved (a restored backup, a downgrade): announce it again, counting from now.
			_, err = tx.Exec(`UPDATE findings SET severity = ?, score = ?, fixed_in = ?, first_seen = ?, last_seen = ?, clean_runs = 0,
				notified_at = NULL, resolved_at = NULL, resolution = NULL, resolve_notified = 0
				WHERE location = ? AND component = ? AND version = ? AND advisory_id = ?`,
				f.Severity, f.Score, f.FixedIn, now, now, f.Location, f.Component, f.Version, f.AdvisoryID)
			changes.New = append(changes.New, Event{Kind: New, Finding: f, FirstSeen: run.Now})
		default:
			_, err = tx.Exec(`UPDATE findings SET severity = ?, score = ?, fixed_in = ?, last_seen = ?, clean_runs = 0
				WHERE location = ? AND component = ? AND version = ? AND advisory_id = ?`,
				f.Severity, f.Score, f.FixedIn, now, f.Location, f.Component, f.Version, f.AdvisoryID)
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

const storedColumns = `location, component, version, advisory_id, COALESCE(severity, ''), COALESCE(score, 0), COALESCE(fixed_in, ''),
	first_seen, clean_runs, COALESCE(resolution, '')`

func query(q interface {
	Query(string, ...any) (*sql.Rows, error)
}, where string, args ...any) ([]stored, error) {
	rows, err := q.Query(`SELECT `+storedColumns+` FROM findings WHERE `+where+` ORDER BY location, component, advisory_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []stored
	for rows.Next() {
		var s stored
		var first int64
		if err := rows.Scan(&s.Location, &s.Component, &s.Version, &s.AdvisoryID, &s.Severity, &s.Score, &s.FixedIn,
			&first, &s.cleanRuns, &s.resolution); err != nil {
			return nil, err
		}
		s.firstSeen = time.Unix(first, 0)
		out = append(out, s)
	}
	return out, rows.Err()
}

func openFindings(tx *sql.Tx) ([]stored, error) {
	return query(tx, `resolved_at IS NULL`)
}

func (s *Store) Pending(now time.Time, renotify time.Duration) ([]Event, error) {
	var events []Event

	fresh, err := query(s.db, `resolved_at IS NULL AND notified_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	for _, f := range fresh {
		events = append(events, Event{Kind: New, Finding: f.Finding, FirstSeen: f.firstSeen, DaysOpen: days(f.firstSeen, now)})
	}
	resolved, err := query(s.db, `resolved_at IS NOT NULL AND resolve_notified = 0 AND notified_at IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	for _, f := range resolved {
		events = append(events, Event{Kind: Kind(f.resolution), Finding: f.Finding, FirstSeen: f.firstSeen, DaysOpen: days(f.firstSeen, now)})
	}

	if renotify > 0 {
		due, err := query(s.db, `resolved_at IS NULL AND notified_at IS NOT NULL AND notified_at <= ? AND UPPER(severity) IN ('CRITICAL', 'HIGH')`,
			now.Add(-renotify).Unix())
		if err != nil {
			return nil, fmt.Errorf("state: %w", err)
		}
		for _, f := range due {
			events = append(events, Event{Kind: StillOpen, Finding: f.Finding, FirstSeen: f.firstSeen, DaysOpen: days(f.firstSeen, now)})
		}
	}
	return events, nil
}

func (s *Store) MarkDelivered(events []Event, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	defer tx.Rollback()

	for _, ev := range events {
		set := `notified_at = ?`
		if ev.Kind == Fixed || ev.Kind == Removed {
			set = `resolve_notified = 1, notified_at = COALESCE(notified_at, ?)`
		}
		if _, err := tx.Exec(`UPDATE findings SET `+set+` WHERE location = ? AND component = ? AND version = ? AND advisory_id = ?`,
			now.Unix(), ev.Location, ev.Component, ev.Version, ev.AdvisoryID); err != nil {
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
