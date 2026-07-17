//go:build windows

package cloudvm

import "os/exec"

// setProcessGroup is a no-op on Windows. The Firecracker backend is Linux/KVM
// only; this stub just lets the package cross-compile.
func setProcessGroup(*exec.Cmd) {}
