//go:build windows

package main

// tightenFileMask is a no-op on Windows, which has no umask; file ACLs govern
// access there instead.
func tightenFileMask() {}
