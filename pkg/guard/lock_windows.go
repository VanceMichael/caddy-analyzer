//go:build windows

package guard

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes a blocking exclusive byte-range lock on f. The range is
// advisory across processes that use the same lock file.
func lockFile(f *os.File) error {
	var ol windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK,
		0, ^uint32(0), ^uint32(0), &ol)
}

func unlockFile(f *os.File) error {
	var ol windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, ^uint32(0), ^uint32(0), &ol)
}
