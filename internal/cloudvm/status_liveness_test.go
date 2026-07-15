package cloudvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A provider-running VM with an unreachable in-guest supervisor has
// indeterminate liveness. Status returns an error so the executor's bounded
// tolerance handles brief saturation without heartbeating a permanently lost
// control channel forever.
func TestStatus_SSHFailureWhileProviderRunningIsBoundedError(t *testing.T) {
	binDir := t.TempDir()
	ssh := filepath.Join(binDir, "ssh")
	require.NoError(t, os.WriteFile(ssh, []byte("#!/bin/sh\nexit 255\n"), 0o755))
	t.Setenv("PATH", binDir)

	provider := NewMockProvider(ProviderHetzner)
	provider.vms["vm-running"] = &VMInfo{
		ID:        "vm-running",
		State:     VMStateRunning,
		CreatedAt: time.Now().UTC(),
	}
	a := NewCloudVMAdapter(provider, Config{ProviderID: ProviderHetzner})
	h := &adapter.RunHandle{State: &CloudVMState{
		VMID:        "vm-running",
		IP:          "192.0.2.10",
		SSHUser:     "root",
		WorkloadPID: 42,
	}}

	state, err := a.Status(context.Background(), h)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh liveness probe failed")
	assert.Equal(t, types.RunStateRunning, state)
}
