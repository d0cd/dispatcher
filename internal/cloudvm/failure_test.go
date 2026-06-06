package cloudvm

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/stretchr/testify/assert"
)

func TestCloudVMAdapter_FailureDetails_ExitCodeRead(t *testing.T) {
	state := &CloudVMState{
		Provider:         ProviderHetzner,
		VMID:             "vm-test",
		LastExitCode:     2,
		LastExitCodeRead: true,
	}
	a := &CloudVMAdapter{}
	fd := a.FailureDetails(&adapter.RunHandle{State: state})
	assert.Equal(t, 2, fd.ExitCode)
	assert.Empty(t, fd.Signal, "clean non-zero exit shouldn't masquerade as a signal")
	assert.Contains(t, fd.Message, "code 2")
	assert.Contains(t, fd.Message, "hetzner")
	assert.Equal(t, adapter.FailurePermanent, adapter.ClassifyFailure(fd),
		"workload-level non-zero exit should classify as permanent (no auto-retry)")
}

func TestCloudVMAdapter_FailureDetails_ExitCodeUnreadable(t *testing.T) {
	// The runner script couldn't write the exit-code file — typical when the
	// process was OOM-killed or terminated externally. We surface this as a
	// SIGKILL hint so the classifier picks "transient" and --retry-transient
	// gets a chance.
	state := &CloudVMState{
		Provider:         ProviderAWS,
		VMID:             "vm-test",
		LastExitCodeRead: false,
	}
	a := &CloudVMAdapter{}
	fd := a.FailureDetails(&adapter.RunHandle{State: state})
	assert.Equal(t, "SIGKILL", fd.Signal)
	assert.Contains(t, fd.Message, "OOM")
	assert.Equal(t, adapter.FailureTransient, adapter.ClassifyFailure(fd))
}

func TestCloudVMAdapter_FailureDetails_SuccessfulRunNoFailure(t *testing.T) {
	// Exit code 0 + read: zero FailureDetails. Caller checks RunState anyway,
	// but make sure we don't accidentally report a phantom failure.
	state := &CloudVMState{
		Provider:         ProviderGCP,
		LastExitCode:     0,
		LastExitCodeRead: true,
	}
	a := &CloudVMAdapter{}
	fd := a.FailureDetails(&adapter.RunHandle{State: state})
	assert.Equal(t, 0, fd.ExitCode)
	assert.Empty(t, fd.Signal)
	assert.Empty(t, fd.Message)
}

func TestRemoteExitCodePath(t *testing.T) {
	state := &CloudVMState{RemoteDir: "/tmp/dispatcher/run_abc"}
	assert.Equal(t, "/tmp/dispatcher/run_abc/dispatcher.exitcode", remoteExitCodePath(state))
}
