//go:build !windows

package adapter

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcessGroup makes the child the leader of a new process group so its whole
// tree can be signalled at once on Terminate.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateProcess signals the child's process group (SIGTERM), falling back to
// killing just the process if the group id can't be resolved.
func terminateProcess(p *os.Process) error {
	if pgid, err := syscall.Getpgid(p.Pid); err == nil {
		return syscall.Kill(-pgid, syscall.SIGTERM)
	}
	return p.Kill()
}
