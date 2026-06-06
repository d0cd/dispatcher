package cloudvm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPlan() *types.Plan {
	return &types.Plan{
		APIVersion: "dispatcher.dev/v1",
		Kind:       "Plan",
		Metadata: types.PlanMetadata{
			ID:        "plan_cloud_test",
			CreatedAt: time.Now().UTC(),
			CreatedBy: "test",
		},
		Workload: types.WorkloadSpec{
			Name:         "test-workload",
			DetectedKind: types.WorkloadKindScript,
			Runtime:      types.RuntimePython,
			Source:       types.WorkloadSource{Type: "repo", Path: "/tmp/test"},
			Entrypoints:  []string{"main.py"},
		},
		Recommendation: &types.Recommendation{
			Target: "hetzner-vm",
		},
	}
}

func TestMockProvider_CreateAndDestroy(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	ctx := context.Background()

	vm, err := mock.CreateVM(ctx, VMOptions{
		Name: "test-vm",
		Tags: map[string]string{"dispatcher": "true", "dispatcher-run-id": "run_1"},
	})
	require.NoError(t, err)
	assert.Equal(t, VMStateRunning, vm.State)
	assert.NotEmpty(t, vm.ID)
	assert.NotEmpty(t, vm.IP)
	assert.Equal(t, 1, mock.VMCount())

	info, err := mock.GetVM(ctx, vm.ID)
	require.NoError(t, err)
	assert.Equal(t, VMStateRunning, info.State)

	require.NoError(t, mock.DestroyVM(ctx, vm.ID))
	assert.Equal(t, 0, mock.VMCount())

	info, err = mock.GetVM(ctx, vm.ID)
	require.NoError(t, err)
	assert.Equal(t, VMStateTerminated, info.State)
}

func TestMockProvider_ListVMs(t *testing.T) {
	mock := NewMockProvider(ProviderAWS)
	ctx := context.Background()

	_, _ = mock.CreateVM(ctx, VMOptions{
		Name: "vm-a",
		Tags: map[string]string{"dispatcher": "true", "dispatcher-run-id": "run_1"},
	})
	_, _ = mock.CreateVM(ctx, VMOptions{
		Name: "vm-b",
		Tags: map[string]string{"dispatcher": "true", "dispatcher-run-id": "run_2"},
	})
	_, _ = mock.CreateVM(ctx, VMOptions{
		Name: "vm-c",
		Tags: map[string]string{"other": "true"},
	})

	vms, err := mock.ListVMs(ctx, map[string]string{"dispatcher": "true"})
	require.NoError(t, err)
	assert.Len(t, vms, 2)
}

func TestMockProvider_Errors(t *testing.T) {
	mock := NewMockProvider(ProviderGCP)
	mock.CreateErr = assert.AnError
	ctx := context.Background()

	_, err := mock.CreateVM(ctx, VMOptions{Name: "test"})
	assert.Error(t, err)
}

func TestCloudVMAdapter_Validate(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner})

	v, err := a.Validate(context.Background(), types.WorkloadSpec{})
	require.NoError(t, err)
	assert.True(t, v.IsValid())
}

func TestCloudVMAdapter_Validate_CLIFail(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	mock.CLIErr = assert.AnError
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner})

	v, err := a.Validate(context.Background(), types.WorkloadSpec{})
	assert.Error(t, err)
	assert.Equal(t, types.ValidationFail, v.Credentials)
}

func TestCloudVMAdapter_EstimateCost(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner})

	est, err := a.EstimateCost(context.Background(), types.WorkloadSpec{DetectedKind: types.WorkloadKindScript})
	require.NoError(t, err)
	assert.Greater(t, est.Value, 0.0)
	assert.Equal(t, "USD", est.Currency)

	est2, err := a.EstimateCost(context.Background(), types.WorkloadSpec{DetectedKind: types.WorkloadKindService})
	require.NoError(t, err)
	assert.Greater(t, est2.Value, est.Value) // 24h > 1h
}

func TestCloudVMAdapter_Reconnect(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner})

	state := &CloudVMState{
		Provider:   ProviderHetzner,
		VMID:       "mock-hetzner-1",
		IP:         "10.0.0.1",
		SSHKeyPath: "/tmp/key",
		SSHUser:    "root",
		SSHPort:    22,
		RemoteDir:  "/tmp/dispatcher/plan_1",
	}
	raw, err := json.Marshal(state)
	require.NoError(t, err)

	handle, err := a.Reconnect(context.Background(), "mock-hetzner-1", raw)
	require.NoError(t, err)
	assert.Equal(t, "mock-hetzner-1", handle.ID)
	assert.Equal(t, "hetzner-vm", handle.TargetID)

	reconState := handle.State.(*CloudVMState)
	assert.Equal(t, "10.0.0.1", reconState.IP)
	assert.Equal(t, ProviderHetzner, reconState.Provider)
}

func TestCloudVMAdapter_Cleanup(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner})
	ctx := context.Background()

	vm, err := mock.CreateVM(ctx, VMOptions{Name: "test-vm"})
	require.NoError(t, err)
	assert.Equal(t, 1, mock.VMCount())

	handle := &adapter.RunHandle{
		ID:       vm.ID,
		TargetID: "hetzner-vm",
		State:    &CloudVMState{Provider: ProviderHetzner, VMID: vm.ID},
	}

	result, err := a.Cleanup(ctx, handle)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 0, mock.VMCount())
}

func TestCloudVMAdapter_Cleanup_Idempotent(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner})

	handle := &adapter.RunHandle{
		ID:       "nonexistent",
		TargetID: "hetzner-vm",
		State:    &CloudVMState{Provider: ProviderHetzner, VMID: "nonexistent"},
	}

	result, err := a.Cleanup(context.Background(), handle)
	require.NoError(t, err)
	assert.True(t, result.Success)
}

func TestCloudVMAdapter_ListResources(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner})
	ctx := context.Background()

	_, _ = mock.CreateVM(ctx, VMOptions{
		Name: "dispatcher-vm",
		Tags: map[string]string{"dispatcher": "true", "dispatcher-run-id": "run_1"},
	})

	resources, err := a.ListResources(ctx)
	require.NoError(t, err)
	assert.Len(t, resources, 1)
	assert.Equal(t, "run_1", resources[0].RunID)
}

func TestCloudVMState_Serialization(t *testing.T) {
	state := &CloudVMState{
		Provider:     ProviderAWS,
		VMID:         "i-abc123",
		IP:           "54.1.2.3",
		SSHKeyPath:   "/home/user/.dispatcher/keys/dispatcher-plan_1",
		SSHUser:      "ubuntu",
		SSHPort:      22,
		Region:       "us-east-1",
		InstanceType: "t3.medium",
		RemoteDir:    "/tmp/dispatcher/plan_1",
		LogPath:      "/tmp/dispatcher/plan_1/dispatcher.log",
		WorkloadPID:  12345,
		CreatedAt:    time.Now().UTC(),
	}

	raw, err := state.MarshalHandleState()
	require.NoError(t, err)

	loaded, err := UnmarshalCloudVMState(raw)
	require.NoError(t, err)
	assert.Equal(t, state.VMID, loaded.VMID)
	assert.Equal(t, state.IP, loaded.IP)
	assert.Equal(t, state.WorkloadPID, loaded.WorkloadPID)
	assert.Equal(t, state.Provider, loaded.Provider)
}

func TestWatchdogCloudInit(t *testing.T) {
	script := WatchdogCloudInit(30 * time.Minute)
	assert.Contains(t, script, "dispatcher-watchdog-deadline")
	assert.Contains(t, script, "shutdown -h now")
	assert.Contains(t, script, "sleep 60")
}

func TestProviderBaseRates(t *testing.T) {
	assert.Greater(t, providerBaseRate(ProviderAWS), 0.0)
	assert.Greater(t, providerBaseRate(ProviderGCP), 0.0)
	assert.Greater(t, providerBaseRate(ProviderAzure), 0.0)
	assert.Greater(t, providerBaseRate(ProviderHetzner), 0.0)
	assert.Less(t, providerBaseRate(ProviderHetzner), providerBaseRate(ProviderAWS))
}
