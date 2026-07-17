//go:build windows

package cost

import (
	"os"

	"golang.org/x/sys/windows"
)

// flockExclusive takes a blocking exclusive lock over the whole file via
// LockFileEx, matching the Unix syscall.Flock(LOCK_EX) advisory-lock semantics
// so concurrent cost-history appends/compactions don't corrupt the JSONL.
func flockExclusive(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK, 0, ^uint32(0), ^uint32(0), &windows.Overlapped{})
}

func flockUnlock(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, ^uint32(0), ^uint32(0), &windows.Overlapped{})
}
