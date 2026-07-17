//go:build !windows

package cloudvm

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the launched process in its own group so teardown can
// signal the whole tree. Firecracker is a Linux/KVM-only backend; this exists so
// the package still cross-compiles on other platforms.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
