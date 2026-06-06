//go:build windows

package cost

import "os"

func flockExclusive(f *os.File) error { return nil }
func flockUnlock(f *os.File) error    { return nil }
