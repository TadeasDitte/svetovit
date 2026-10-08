package detector

import (
	"io/fs"
	"os"
)

// Listing caches directory listings so a site scan reads each directory at most once. It is not safe for
// concurrent use; a scan uses one Listing per site.
type Listing struct {
	// Pace, if set, is called before every directory read and version file open, to throttle the scan.
	Pace func()

	dirs map[string]listed
}

type listed struct {
	entries []fs.DirEntry
	err     error
}

func NewListing() *Listing {
	return &Listing{dirs: map[string]listed{}}
}

// Seed records a listing that was already read elsewhere, such as during the walk.
func (l *Listing) Seed(dir string, entries []fs.DirEntry) {
	l.dirs[dir] = listed{entries: entries}
}

func (l *Listing) ReadDir(dir string) ([]fs.DirEntry, error) {
	if r, ok := l.dirs[dir]; ok {
		return r.entries, r.err
	}
	l.pace()
	entries, err := os.ReadDir(dir)
	l.dirs[dir] = listed{entries: entries, err: err}
	return entries, err
}

func (l *Listing) pace() {
	if l.Pace != nil {
		l.Pace()
	}
}
