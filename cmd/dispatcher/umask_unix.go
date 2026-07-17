//go:build !windows

package main

import "syscall"

// tightenFileMask lowers the process file-creation mask so any write that
// doesn't pass explicit perms still lands at 0600 rather than inheriting a loose
// shell umask.
func tightenFileMask() {
	syscall.Umask(0o077)
}
