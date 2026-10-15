package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type stateEntry struct {
	IP   string    `json:"ip"`
	When time.Time `json:"when"`
}

// stateFile owns the durable block list at path. Every read-modify-write
// transaction goes through withLock, which serializes cooperating processes
// (the guard daemon and the block/unban commands) via an exclusive flock on
// a sidecar lock file. The in-process mutex additionally serializes callers
// inside one process (the daemon's tick, expiry loop and shutdown flush).
type stateFile struct {
	mu   sync.Mutex
	path string
}

func newStateFile(path string) *stateFile {
	return &stateFile{path: path}
}

// withLock runs fn while holding the in-process mutex and an exclusive
// cross-process lock. fn must not call withLock again (locks are not
// reentrant) and must perform every read and write of the state file while
// the lock is held.
func (s *stateFile) withLock(fn func() error) error {
	if s == nil || s.path == "" {
		return fn()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Dir(s.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("state directory: %w", err)
		}
	}
	// A dedicated lock file (never renamed) backs the cross-process lock.
	// The state file itself is replaced via rename, so locking it directly
	// would leave holders pointing at a stale inode.
	lock, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open state lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := lockFile(lock); err != nil {
		return fmt.Errorf("acquire state lock: %w", err)
	}
	defer func() { _ = unlockFile(lock) }()
	return fn()
}

// load reads and validates the state file in its own locked transaction.
// A missing file and an empty file both mean "no entries"; corrupt JSON is
// an error so callers never silently overwrite unreadable state.
func (s *stateFile) load() ([]stateEntry, error) {
	if s == nil || s.path == "" {
		return nil, nil
	}
	var entries []stateEntry
	err := s.withLock(func() error {
		var err error
		entries, err = s.loadLocked()
		return err
	})
	return entries, err
}

// loadLocked reads the state file. Callers must hold the cross-process lock.
func (s *stateFile) loadLocked() ([]stateEntry, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		// Empty (or whitespace-only) state file: nothing tracked yet.
		return nil, nil
	}
	var entries []stateEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("invalid state json: %w", err)
	}
	return entries, nil
}

// saveEntries writes entries in its own locked transaction. It is a
// standalone file-only operation; convergent firewall+state decisions use
// writeLocked inside a larger withLock transaction.
func (s *stateFile) saveEntries(entries []stateEntry) error {
	if s == nil || s.path == "" {
		return nil
	}
	return s.withLock(func() error {
		return s.writeLocked(entries)
	})
}

// writeLocked durably replaces the state file with entries: write to a
// temp file in the same directory, fsync, chmod, atomic rename, fsync the
// directory. On any error the temp file is removed and the previous state
// file stays byte-for-byte intact — a caller can never observe half JSON.
// Callers must hold the cross-process lock.
func (s *stateFile) writeLocked(entries []stateEntry) error {
	if entries == nil {
		entries = []stateEntry{}
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// entriesToMap converts the on-disk entry list to an ip -> expiry map
// (zero time = permanent block).
func entriesToMap(entries []stateEntry) map[string]time.Time {
	m := make(map[string]time.Time, len(entries))
	for _, e := range entries {
		m[e.IP] = e.When
	}
	return m
}

// mapToEntries converts an ip -> expiry map back to the stable JSON-array
// wire format. Output is sorted so unrelated transactions do not churn the
// file and so diffs are reviewable.
func mapToEntries(m map[string]time.Time) []stateEntry {
	entries := make([]stateEntry, 0, len(m))
	for ip, when := range m {
		entries = append(entries, stateEntry{IP: ip, When: when})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].IP < entries[j].IP })
	return entries
}
