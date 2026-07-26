package adapter

import (
	"context"
	"os/exec"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runLocalProcess starts a child process via exec and returns the localState
// once cmd.Wait has populated ProcessState. Used to drive FailureDetails
// without going through the full adapter Execute path.
func runLocalProcess(t *testing.T, name string, args ...string) *localState {
	t.Helper()
	cmd := exec.Command(name, args...)
	setProcessGroup(cmd) // build-tagged: no-op on Windows (Setpgid is Unix-only)
	require.NoError(t, cmd.Start())
	_ = cmd.Wait() // ignore exit error — that's the point
	return &localState{cmd: cmd}
}

func TestLocalAdapter_FailureDetails_Success(t *testing.T) {
	ls := runLocalProcess(t, "true")
	a := &LocalAdapter{}
	fd := a.FailureDetails(&RunHandle{State: ls})
	assert.Equal(t, 0, fd.ExitCode, "successful exit should report 0")
	assert.Empty(t, fd.Signal)
}

func TestLocalAdapter_FailureDetails_NonZeroExit(t *testing.T) {
	// `false` exits with code 1 on Unix.
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only test")
	}
	ls := runLocalProcess(t, "false")
	a := &LocalAdapter{}
	fd := a.FailureDetails(&RunHandle{State: ls})
	assert.Equal(t, 1, fd.ExitCode)
	assert.Empty(t, fd.Signal)
	assert.Contains(t, fd.Message, "exited with code 1")
}

func TestLocalAdapter_FailureDetails_KilledBySignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only signal handling")
	}
	// Start sleep, kill it, then inspect state.
	cmd := exec.CommandContext(context.Background(), "sleep", "60")
	setProcessGroup(cmd)
	require.NoError(t, cmd.Start())
	require.NoError(t, cmd.Process.Signal(syscall.SIGKILL))
	_ = cmd.Wait()
	ls := &localState{cmd: cmd}

	a := &LocalAdapter{}
	fd := a.FailureDetails(&RunHandle{State: ls})
	assert.Equal(t, "killed", fd.Signal)
	assert.Contains(t, fd.Message, "killed by")
}

func TestLocalAdapter_FailureDetails_NoProcessStateYet(t *testing.T) {
	// State with no ProcessState — should return a Message rather than nil.
	a := &LocalAdapter{}
	fd := a.FailureDetails(&RunHandle{State: &localState{}})
	assert.Contains(t, fd.Message, "not available")
}
