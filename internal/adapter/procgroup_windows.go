//go:build windows

package adapter

import (
	"os"
	"os/exec"
)

// setProcessGroup is a no-op on Windows: process-group/job-object semantics
// differ from Unix and dispatcher does not manage a group here, so Terminate
// kills the single child process.
func setProcessGroup(*exec.Cmd) {}

// terminateProcess kills the child. Windows has no SIGTERM/process-group
// equivalent to the Unix path, so this is a hard kill.
func terminateProcess(p *os.Process) error {
	return p.Kill()
}
