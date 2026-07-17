//go:build !windows

package state

import (
	"os"
	"syscall"
)

// ownedByOther reports whether the directory described by info is owned by a
// different uid than the current process. Used to refuse a pre-existing state
// directory an attacker may have planted on a shared host.
func ownedByOther(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) != os.Getuid()
}
