//go:build windows

package state

import "os"

// ownedByOther is a no-op on Windows: access control is by ACL, not a uid the
// FileInfo exposes, so the uid-ownership model doesn't apply. Directory creation
// (0700 via MkdirAll) and the parent's permissions remain the boundary there.
func ownedByOther(os.FileInfo) bool { return false }
