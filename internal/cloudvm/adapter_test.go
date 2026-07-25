package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
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

// A spot VM that the provider reclaims mid-run surfaces as VMStateTerminated.
// Status must mark the state Reclaimed, and FailureDetails must report it as a
// reclaim so ClassifyFailure returns transient and --retry-transient re-provisions.
func TestCloudVMAdapter_SpotReclaim(t *testing.T) {
	mock := NewMockProvider(ProviderGCP)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderGCP})

	// VMID unknown to the mock → GetVM returns VMStateTerminated (the reclaim).
	state := &CloudVMState{Provider: ProviderGCP, VMID: "reclaimed-vm", Spot: true}
	handle := &adapter.RunHandle{ID: "reclaimed-vm", TargetID: "gcp-vm", State: state}

	st, err := a.Status(context.Background(), handle)
	require.NoError(t, err)
	assert.Equal(t, types.RunStateExecutionFailed, st)
	assert.True(t, state.Reclaimed, "a terminated spot VM must be marked reclaimed")

	fd := a.FailureDetails(handle)
	assert.True(t, fd.Reclaimed, "FailureDetails must report the reclaim")
	assert.Equal(t, adapter.FailureTransient, adapter.ClassifyFailure(fd))
}

// A non-spot VM found terminated is not attributed to a reclaim.
func TestCloudVMAdapter_NonSpotTerminatedNotReclaimed(t *testing.T) {
	mock := NewMockProvider(ProviderGCP)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderGCP})

	state := &CloudVMState{Provider: ProviderGCP, VMID: "gone-vm", Spot: false}
	handle := &adapter.RunHandle{ID: "gone-vm", TargetID: "gcp-vm", State: state}

	st, err := a.Status(context.Background(), handle)
	require.NoError(t, err)
	assert.Equal(t, types.RunStateExecutionFailed, st)
	assert.False(t, state.Reclaimed, "non-spot termination must not be marked a reclaim")
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

// When DestroyVM fails, Cleanup must report failure (Success=false + the
// provider error) rather than swallowing it — that signal is what tells the
// operator a billable VM may be orphaned.
func TestCloudVMAdapter_Cleanup_DestroyFailureSurfaces(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	mock.DestroyErr = fmt.Errorf("provider quota exhausted")
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner})

	handle := &adapter.RunHandle{
		ID:       "vm-1",
		TargetID: "hetzner-vm",
		State:    &CloudVMState{Provider: ProviderHetzner, VMID: "vm-1"},
	}

	result, err := a.Cleanup(context.Background(), handle)
	require.NoError(t, err, "Cleanup reports the failure via the result, not a returned error")
	require.NotNil(t, result)
	assert.False(t, result.Success, "a failed DestroyVM must mark the cleanup unsuccessful")
	assert.Contains(t, result.Errors, "provider quota exhausted")
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

func TestCloudVMAdapter_DestroyResource_RefusesUnowned(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner})
	ctx := context.Background()

	// A resource that dispatcher did NOT create (no dispatcher=true tag) — e.g.
	// another project's VM surfaced by a listing. Destroying it would be
	// irreversible loss of something we don't own.
	vm, _ := mock.CreateVM(ctx, VMOptions{
		Name: "someone-elses-vm",
		Tags: map[string]string{"owner": "other-team"},
	})

	err := a.DestroyResource(ctx, adapter.ResourceInfo{
		ResourceID: vm.ID,
		Provider:   string(ProviderHetzner),
		Kind:       adapter.ResourceInstance,
		Tags:       vm.Tags,
	})

	require.Error(t, err, "must refuse to destroy a resource dispatcher doesn't own")
	assert.Contains(t, err.Error(), "not dispatcher-owned")
	if _, ok := mock.vms[vm.ID]; !ok {
		t.Fatal("DestroyVM was called on an unowned resource; the ownership guard failed")
	}
}

func TestCloudVMAdapter_DestroyResource_DestroysOwned(t *testing.T) {
	mock := NewMockProvider(ProviderHetzner)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner})
	ctx := context.Background()

	vm, _ := mock.CreateVM(ctx, VMOptions{
		Name: "dispatcher-vm",
		Tags: map[string]string{"dispatcher": "true", "dispatcher-run-id": "run_1"},
	})

	err := a.DestroyResource(ctx, adapter.ResourceInfo{
		ResourceID: vm.ID,
		Provider:   string(ProviderHetzner),
		Kind:       adapter.ResourceInstance,
		Tags:       vm.Tags,
	})

	require.NoError(t, err)
	if _, ok := mock.vms[vm.ID]; ok {
		t.Fatal("a dispatcher-owned instance should have been destroyed")
	}
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
	script := WatchdogCloudInit(30*time.Minute, "ubuntu", DefaultWatchdogSelfDestruct)
	assert.Contains(t, script, "watchdog-deadline")
	assert.Contains(t, script, "shutdown -h now")
	assert.Contains(t, script, "sleep 60")

	// The deadline must live on durable storage, not tmpfs, so it survives
	// a reboot.
	assert.Contains(t, script, "/var/lib/dispatcher")
	assert.NotContains(t, script, "/var/run/")

	// The poll loop must be installed under systemd (Restart=always, enabled)
	// so it is re-launched after a reboot rather than dying with the boot
	// shell.
	assert.Contains(t, script, "systemctl enable")
	assert.Contains(t, script, "Restart=always")

	// cloud-init writes the deadline as root; renewal SSHes in as the login
	// user (non-root on AWS/GCP/Azure/OCI), so the file must be handed to that
	// user or `echo > deadline` fails with permission denied and the
	// self-destruct never renews.
	assert.Contains(t, script, "chown ubuntu "+watchdogDeadlinePath)
}

func TestWatchdogCloudInit_RootLoginNeedsNoChown(t *testing.T) {
	// Where the login user is root (Hetzner/Firecracker) the file is already
	// root-owned, so no chown is emitted.
	script := WatchdogCloudInit(30*time.Minute, "root", DefaultWatchdogSelfDestruct)
	assert.NotContains(t, script, "chown root")
}

// watchdogSelfDestructFor picks the per-provider expiry action: every provider
// halts the OS except Azure, where a bare halt leaves the VM Stopped(allocated)
// and still compute-billing, so the guest must deallocate itself via IMDS.
func TestWatchdogSelfDestructFor(t *testing.T) {
	azure := watchdogSelfDestructFor(ProviderAzure)
	assert.Contains(t, azure, "deallocate", "Azure must deallocate, not just halt")
	assert.Contains(t, azure, "shutdown -h now", "and still halt as a fallback")

	for _, p := range []ProviderID{ProviderAWS, ProviderGCP, ProviderHetzner, ProviderOCI} {
		sd := watchdogSelfDestructFor(p)
		assert.Equal(t, DefaultWatchdogSelfDestruct, sd, "%s should halt, not deallocate", p)
		assert.NotContains(t, sd, "deallocate")
	}
}

// The Azure expiry action must obtain a managed-identity token from IMDS, read
// its own subscription/RG/name from instance metadata, and POST deallocate to
// ARM — then fall back to halting the OS if any of that is unavailable.
func TestWatchdogCloudInit_AzureDeallocate(t *testing.T) {
	script := WatchdogCloudInit(30*time.Minute, "dispatcher", watchdogSelfDestructFor(ProviderAzure))
	assert.Contains(t, script, "identity/oauth2/token", "must fetch an IMDS managed-identity token")
	assert.Contains(t, script, "management.azure.com", "must call ARM")
	assert.Contains(t, script, "/deallocate?api-version=", "must POST the deallocate action")
	assert.Contains(t, script, "instance/compute/$1", "must read its own metadata from IMDS")
	assert.Contains(t, script, "_az_meta subscriptionId", "must read its own subscription id")
	assert.Contains(t, script, "shutdown -h now", "must still halt as a fallback")
}

func TestProviderBaseRates(t *testing.T) {
	assert.Greater(t, providerBaseRate(ProviderAWS), 0.0)
	assert.Greater(t, providerBaseRate(ProviderGCP), 0.0)
	assert.Greater(t, providerBaseRate(ProviderAzure), 0.0)
	assert.Greater(t, providerBaseRate(ProviderHetzner), 0.0)
	assert.Less(t, providerBaseRate(ProviderHetzner), providerBaseRate(ProviderAWS))
}

// rsync exits 23 (partial transfer) when a declared but optional output wasn't
// produced by the workload — that must be classified so Artifacts can skip it
// instead of reporting a spurious error.
func TestRsyncExitCode(t *testing.T) {
	assert.Equal(t, 23, rsyncExitCode(execCommandExit(t, 23)), "rsync partial-transfer code must be recognized")
	assert.Equal(t, 1, rsyncExitCode(execCommandExit(t, 1)), "a real failure keeps its own exit code")
	assert.Equal(t, -1, rsyncExitCode(exec.Command("dispatcher-no-such-binary-xyz").Run()),
		"a non-exit error (binary missing) is not an exit code")
}

func execCommandExit(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	require.Error(t, err)
	return err
}

// The workload runs at lower CPU priority so it can't starve the on-VM control
// plane (sshd, watchdog renewal, log streaming) under saturation.
func TestNiceCommand_WrapsWorkload(t *testing.T) {
	assert.Equal(t, "nice -n 10 python main.py", niceCommand("python main.py"))
}

// parseOOMEvidence confirms an OOM only from real kernel/cgroup evidence — a
// kernel OOM-killer line or a non-zero cgroup oom_kill counter — and preserves
// uncertainty (not OOM) when the evidence is absent.
func TestParseOOMEvidence(t *testing.T) {
	killLine := "[12345.6] Out of memory: Killed process 4242 (python) total-vm:16000000kB"
	ev := parseOOMEvidence(killLine)
	assert.True(t, ev.oomKilled, "a kernel OOM-killer line confirms OOM")
	assert.Contains(t, ev.summary, "Killed process")

	assert.True(t, parseOOMEvidence("oom_kill 3\n").oomKilled, "a non-zero cgroup oom_kill counter confirms OOM")
	assert.False(t, parseOOMEvidence("oom_kill 0\n").oomKilled, "oom_kill 0 is not an OOM")
	assert.False(t, parseOOMEvidence("").oomKilled, "no evidence → not OOM (preserve uncertainty)")
	assert.False(t, parseOOMEvidence("some unrelated kernel line").oomKilled)
}
