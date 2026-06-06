package adapter

import (
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

// runSSHLike fabricates a sshState backed by a local process exit. The local
// `ssh` exits with the same code as its remote command (when ssh itself
// succeeds), so a local `false` is a faithful stand-in for "remote command
// exited with code 1 through a healthy SSH connection".
func runSSHLike(t *testing.T, cmdName string, args ...string) *sshState {
	t.Helper()
	cmd := exec.Command(cmdName, args...)
	_ = cmd.Run()
	return &sshState{cmd: cmd}
}

func TestSSHAdapter_FailureDetails_RemoteSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only")
	}
	ss := runSSHLike(t, "true")
	a := &SSHAdapter{}
	fd := a.FailureDetails(&RunHandle{State: ss})
	assert.Equal(t, 0, fd.ExitCode)
	assert.Empty(t, fd.Signal)
}

func TestSSHAdapter_FailureDetails_RemoteNonZero(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only")
	}
	ss := runSSHLike(t, "false")
	a := &SSHAdapter{}
	fd := a.FailureDetails(&RunHandle{State: ss})
	assert.Equal(t, 1, fd.ExitCode)
	assert.Empty(t, fd.Signal, "remote-side failure should not look like transport failure")
	assert.Contains(t, fd.Message, "remote command")
}

func TestSSHAdapter_FailureDetails_TransportFailureClassifiesTransient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only")
	}
	// Simulate ssh exit 255 (transport failure) via `sh -c "exit 255"`.
	cmd := exec.Command("sh", "-c", "exit 255")
	_ = cmd.Run()
	ss := &sshState{cmd: cmd}

	a := &SSHAdapter{}
	fd := a.FailureDetails(&RunHandle{State: ss})
	assert.Equal(t, 255, fd.ExitCode)
	assert.Equal(t, "SIGKILL", fd.Signal,
		"exit 255 should look transient so --retry-transient re-attempts the connection")
	assert.Contains(t, fd.Message, "transport")

	// And verify the classifier agrees.
	assert.Equal(t, FailureTransient, ClassifyFailure(fd))
}

func TestSSHAdapter_FailureDetails_NoState(t *testing.T) {
	a := &SSHAdapter{}
	fd := a.FailureDetails(&RunHandle{State: &sshState{}})
	assert.Contains(t, fd.Message, "not available")
}
