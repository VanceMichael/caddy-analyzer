//go:build !windows

package guard

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes a blocking exclusive advisory lock (flock) on f. All
// cooperating binaries must lock the same sidecar path; the lock is
// released automatically when the descriptor is closed.
func lockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}

func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
