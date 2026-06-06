//go:build windows

package run

import "os"

func flockExclusive(f *os.File) error { return nil }
func flockUnlock(f *os.File) error    { return nil }
