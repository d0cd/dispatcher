package run

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSaveRunLogsFailure covers C5: a failed persist at an executor call site
// must surface a warning rather than being silently dropped.
func TestSaveRunLogsFailure(t *testing.T) {
	var buf bytes.Buffer
	dlog.SetOutput(&buf)

	r := NewRun(testPlan())
	r.ID = "bad/id" // invalid run id → Save() returns an error immediately
	saveRun(r)

	assert.Contains(t, buf.String(), "run.save.failed")
	assert.Contains(t, buf.String(), "bad/id")
}

// mockAdapter is a configurable adapter for executor testing.
type mockAdapter struct {
	id                 string
	validateErr        error
	validateResult     types.ValidationResult
	prepareErr         error
	executeErr         error
	statusResult       types.RunState
	statusErr          error
	statusErrsThenOK   int              // return a transient error for the first N Status calls, then statusResult
	statusSequence     []types.RunState // when set, Status returns successive elements (clamped to last)
	statusCalls        int
	terminateCalls     int
	cleanupResult      *adapter.CleanupResult
	cleanupErr         error
	cleanupCalls       int
	executePanic       bool
	executed           bool  // set true on Execute; used to assert non-invocation
	artifactErr        error // when set, Artifacts always fails with it
	artifactErrsThenOK int   // fail the first N Artifacts calls, then succeed
	artifactCalls      int
}

func newMockAdapter() *mockAdapter {
	return &mockAdapter{
		id:             "mock",
		validateResult: adapter.DefaultValidationResult(),
		statusResult:   types.RunStateCompleted,
		cleanupResult:  &adapter.CleanupResult{Success: true},
	}
}

func (m *mockAdapter) ID() string { return m.id }
func (m *mockAdapter) Validate(_ context.Context, _ types.WorkloadSpec) (types.ValidationResult, error) {
	return m.validateResult, m.validateErr
}
func (m *mockAdapter) EstimateCost(_ context.Context, _ types.WorkloadSpec) (types.CostEstimate, error) {
	return types.CostEstimate{}, nil
}
func (m *mockAdapter) Prepare(_ context.Context, _ *types.Plan) error {
	return m.prepareErr
}
func (m *mockAdapter) Execute(_ context.Context, _ *types.Plan) (*adapter.RunHandle, error) {
	m.executed = true
	if m.executePanic {
		panic("adapter panic!")
	}
	if m.executeErr != nil {
		return nil, m.executeErr
	}
	return &adapter.RunHandle{ID: "mock-handle", TargetID: m.id, State: "opaque"}, nil
}
func (m *mockAdapter) Status(_ context.Context, _ *adapter.RunHandle) (types.RunState, error) {
	m.statusCalls++
	if m.statusErrsThenOK > 0 && m.statusCalls <= m.statusErrsThenOK {
		return types.RunStateExecutionFailed, fmt.Errorf("transient status error #%d", m.statusCalls)
	}
	if len(m.statusSequence) > 0 {
		idx := m.statusCalls - 1
		if idx >= len(m.statusSequence) {
			idx = len(m.statusSequence) - 1
		}
		return m.statusSequence[idx], m.statusErr
	}
	return m.statusResult, m.statusErr
}
func (m *mockAdapter) Logs(_ context.Context, _ *adapter.RunHandle, w io.Writer) error {
	fmt.Fprintln(w, "mock log line")
	return nil
}
func (m *mockAdapter) Artifacts(_ context.Context, _ *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
	m.artifactCalls++
	if m.artifactErrsThenOK > 0 && m.artifactCalls <= m.artifactErrsThenOK {
		return nil, fmt.Errorf("transient artifact transport error #%d", m.artifactCalls)
	}
	if m.artifactErr != nil {
		return nil, m.artifactErr
	}
	return []adapter.ArtifactRef{{Name: "collected"}}, nil
}
func (m *mockAdapter) Terminate(_ context.Context, _ *adapter.RunHandle) error {
	m.terminateCalls++
	return nil
}
func (m *mockAdapter) Cleanup(_ context.Context, _ *adapter.RunHandle) (*adapter.CleanupResult, error) {
	m.cleanupCalls++
	return m.cleanupResult, m.cleanupErr
}

type durableEphemeralMock struct {
	*mockAdapter
	watchdogCalls atomic.Int32
}

func (m *durableEphemeralMock) Reconnect(_ context.Context, handleID string, _ json.RawMessage) (*adapter.RunHandle, error) {
	return &adapter.RunHandle{ID: handleID, TargetID: m.id, State: "opaque"}, nil
}
func (m *durableEphemeralMock) ExtendWatchdog(_ context.Context, _ *adapter.RunHandle, ttl time.Duration) (time.Time, error) {
	m.watchdogCalls.Add(1)
	return time.Now().Add(ttl), nil
}
func (m *durableEphemeralMock) ListResources(_ context.Context) ([]adapter.ResourceInfo, error) {
	return nil, nil
}
func (m *durableEphemeralMock) DestroyResource(_ context.Context, _ adapter.ResourceInfo) error {
	return nil
}

func executorTestPlan() *types.Plan {
	return &types.Plan{
		APIVersion: "dispatcher.dev/v1",
		Kind:       "Plan",
		Metadata: types.PlanMetadata{
			ID:        "plan_exec_test",
			CreatedAt: time.Now().UTC(),
			CreatedBy: "test",
		},
		Workload: types.WorkloadSpec{
			Name:         "test",
			DetectedKind: types.WorkloadKindScript,
			Runtime:      types.RuntimePython,
		},
		Recommendation: &types.Recommendation{
			Target:        "mock",
			EstimatedCost: types.CostEstimate{Value: 0, Currency: "USD", Confidence: types.ConfidenceHigh},
		},
	}
}

// persistObserverAdapter records, at Execute time, whether a non-terminal run
// record for this plan was already on disk — i.e. whether a concurrent gc's
// active-run protection (keyed off PlanID, built from persisted records) would
// have covered the VM Execute is about to provision.
type persistObserverAdapter struct {
	*mockAdapter
	recordPersistedAtExecute bool
}

func (m *persistObserverAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	ids, _ := ListRecords()
	for _, id := range ids {
		if rec, err := LoadRecord(id); err == nil && rec.PlanID == p.Metadata.ID && !rec.State.IsTerminal() {
			m.recordPersistedAtExecute = true
		}
	}
	return m.mockAdapter.Execute(ctx, p)
}

// A concurrent `dispatcher gc` builds its active-run set from persisted records
// and keys protection off PlanID. If the run record is not persisted until AFTER
// adapter.Execute returns (which for a cloud/confidential run is the entire
// provision + sealed run), gc sees no record for the live VM's plan id,
// misclassifies the dispatcher-owned VM as an orphan, and destroys it mid-run.
// A non-terminal record must therefore be on disk before Execute is called.
func TestExecutor_PersistsRunRecordBeforeProvisioning(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	m := &persistObserverAdapter{mockAdapter: newMockAdapter()}
	ex := NewExecutor(m)
	r := NewRun(executorTestPlan())
	require.NoError(t, ex.Execute(context.Background(), r, io.Discard))
	assert.True(t, m.recordPersistedAtExecute,
		"a non-terminal run record must be persisted before adapter.Execute so a concurrent gc won't reap the live VM")
}

// A transient artifact-transport blip must not lose a finished job's outputs:
// collection is retried with bounded backoff, so an early failure that later
// succeeds still delivers the artifacts and the run completes normally.
func TestExecutor_ArtifactCollection_RetriesTransient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prev := SetArtifactRetryInterval(time.Millisecond)
	defer func() { SetArtifactRetryInterval(prev) }()

	mock := newMockAdapter()
	mock.artifactErrsThenOK = 2 // first two collections fail, the third succeeds
	ex := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	require.NoError(t, ex.Execute(context.Background(), r, io.Discard))
	assert.Equal(t, types.RunStateCompleted, r.GetState())
	require.Len(t, r.Artifacts, 1, "the retried collection must still deliver the outputs")
	assert.Equal(t, 3, mock.artifactCalls, "collection retried until it succeeded")
	assert.Greater(t, mock.cleanupCalls, 0, "a fully-collected run tears down normally")
}

// When output retrieval fails after retries, dispatcher must NOT destroy the VM
// (that would lose a finished job's outputs). The run ends in ArtifactFailed with
// the VM preserved (not torn down), and it is NOT relabeled a workload failure.
func TestExecutor_ArtifactCollection_PreservesVMOnPersistentFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prev := SetArtifactRetryInterval(time.Millisecond)
	defer func() { SetArtifactRetryInterval(prev) }()

	mock := newMockAdapter()
	mock.artifactErr = fmt.Errorf("scp connection reset")
	ex := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := ex.Execute(context.Background(), r, io.Discard)
	require.Error(t, err, "a failed output retrieval must surface, not be swallowed")
	assert.Equal(t, types.RunStateArtifactFailed, r.GetState(), "artifact retrieval failed — not a workload failure")
	assert.NotEqual(t, types.RunStateExecutionFailed, r.GetState())
	assert.Equal(t, 0, mock.cleanupCalls, "the VM must be preserved (not destroyed) so outputs can still be recovered")
}

func TestExecutor_HappyPath(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	mock := newMockAdapter()
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, types.RunStateCompleted, r.GetState())
	assert.True(t, mock.cleanupCalls > 0, "cleanup should be called")
}

func TestExecutor_ValidationFailure(t *testing.T) {
	mock := newMockAdapter()
	mock.validateErr = fmt.Errorf("docker not available")
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	assert.Error(t, err)
	assert.Equal(t, types.RunStatePlanInvalid, r.GetState())
	assert.Contains(t, r.Error, "docker not available")
}

func TestExecutor_ValidationResultInvalid(t *testing.T) {
	mock := newMockAdapter()
	mock.validateResult = types.ValidationResult{
		Schema:             types.ValidationPass,
		TargetCapabilities: types.ValidationFail,
	}
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	assert.Error(t, err)
	assert.Equal(t, types.RunStatePlanInvalid, r.GetState())
}

func TestExecutor_PrepareFailure(t *testing.T) {
	mock := newMockAdapter()
	mock.prepareErr = fmt.Errorf("build failed")
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	assert.Error(t, err)
	assert.Equal(t, types.RunStatePackageFailed, r.GetState())
}

func TestExecutor_ExecuteFailure(t *testing.T) {
	mock := newMockAdapter()
	mock.executeErr = fmt.Errorf("process start failed")
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	assert.Error(t, err)
	assert.Equal(t, types.RunStateExecutionFailed, r.GetState())
}

// A single transient Status error while polling must NOT tear down a healthy
// run — the executor tolerates a bounded number of consecutive transient errors.
func TestExecutor_ToleratesTransientStatusErrors(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	restore := SetStatusPollInterval(time.Millisecond)
	defer SetStatusPollInterval(restore)

	mock := newMockAdapter()
	mock.statusErrsThenOK = 3 // three transient blips, then the workload is done
	mock.statusResult = types.RunStateCompleted
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	require.NoError(t, err, "transient status errors must be tolerated, not terminal")
	assert.Equal(t, types.RunStateCompleted, r.GetState())
}

func TestExecutor_StatusFailure_CleanupStillRuns(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	restore := SetStatusPollInterval(time.Millisecond)
	defer SetStatusPollInterval(restore)

	mock := newMockAdapter()
	mock.statusErr = fmt.Errorf("status check failed")
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	assert.Error(t, err)
	// Critical: cleanup must still be called even when status fails
	assert.True(t, mock.cleanupCalls > 0, "cleanup must run even on status failure")
}

func TestExecutor_WorkloadFailed_CleanupStillRuns(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	mock := newMockAdapter()
	mock.statusResult = types.RunStateExecutionFailed
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	assert.Error(t, err)
	assert.True(t, mock.cleanupCalls > 0, "cleanup must run even on workload failure")
}

func TestExecutor_CleanupFailure_RetriesAndFails(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	mock := newMockAdapter()
	mock.cleanupResult = &adapter.CleanupResult{Success: false}
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	assert.Error(t, err)
	assert.Equal(t, types.RunStateCleanupFailed, r.GetState())
	// Should retry 3 times
	assert.Equal(t, 3, mock.cleanupCalls, "cleanup should be retried 3 times")
}

func TestExecutor_PanicRecovery(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	mock := newMockAdapter()
	mock.executePanic = true
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	// Should NOT panic — executor recovers — but must surface the crash as an
	// error so the caller (and process exit code) doesn't mistake it for success.
	var err error
	assert.NotPanics(t, func() {
		err = exec.Execute(context.Background(), r, io.Discard)
	})
	require.Error(t, err, "a recovered panic must be returned as an error, not nil")
	assert.Contains(t, err.Error(), "panic")
	assert.Equal(t, types.RunStateExecutionFailed, r.GetState())
	assert.Contains(t, r.Error, "panic")
}

// TestExecutor_PollsUntilTerminal covers the durable-adapter contract: a
// poll-based Status (cloud VM / k8s) returns Running until the workload
// finishes. The executor must keep polling instead of tearing the run down on
// the first Running reading.
func TestExecutor_PollsUntilTerminal(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	restore := SetStatusPollInterval(time.Millisecond)
	defer SetStatusPollInterval(restore)

	mock := newMockAdapter()
	mock.statusSequence = []types.RunState{
		types.RunStateRunning,
		types.RunStateRunning,
		types.RunStateCompleted,
	}
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, types.RunStateCompleted, r.GetState())
	assert.GreaterOrEqual(t, mock.statusCalls, 3, "executor must poll Status until terminal, not tear down on first Running")
}

func TestExecutor_EphemeralDurableRunRenewsWatchdogWhileRunning(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	restore := SetStatusPollInterval(time.Millisecond)
	defer SetStatusPollInterval(restore)

	base := newMockAdapter()
	base.statusSequence = make([]types.RunState, 31)
	for i := range base.statusSequence[:30] {
		base.statusSequence[i] = types.RunStateRunning
	}
	base.statusSequence[30] = types.RunStateCompleted
	mock := &durableEphemeralMock{mockAdapter: base}

	p := executorTestPlan()
	p.Constraints.WatchdogTTL = 9 * time.Millisecond
	r := NewRun(p)
	require.NoError(t, NewExecutor(mock).Execute(context.Background(), r, io.Discard))

	assert.GreaterOrEqual(t, mock.watchdogCalls.Load(), int32(2),
		"an attached durable ephemeral run must renew beyond its initial watchdog deadline")
}

// TestExecutor_PollRespectsContextCancel: a workload that never terminates must
// stop polling when the context is canceled, and cleanup must still run.
func TestExecutor_PollRespectsContextCancel(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	restore := SetStatusPollInterval(time.Millisecond)
	defer SetStatusPollInterval(restore)

	mock := newMockAdapter()
	mock.statusResult = types.RunStateRunning // never terminal
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	err := exec.Execute(ctx, r, io.Discard)
	assert.Error(t, err)
	assert.True(t, mock.cleanupCalls > 0, "cleanup must run when polling is canceled")
}

// TestExecutor_PollRespectsMaxDuration: a workload that never terminates must be
// terminated and reported failed once MaxDuration elapses.
func TestExecutor_PollRespectsMaxDuration(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	restore := SetStatusPollInterval(time.Millisecond)
	defer SetStatusPollInterval(restore)

	mock := newMockAdapter()
	mock.statusResult = types.RunStateRunning // never terminal
	exec := NewExecutor(mock)
	p := executorTestPlan()
	p.Constraints.MaxDuration = 15 * time.Millisecond
	r := NewRun(p)

	err := exec.Execute(context.Background(), r, io.Discard)
	assert.Error(t, err)
	assert.True(t, mock.terminateCalls > 0, "workload must be terminated when MaxDuration elapses")
	assert.True(t, mock.cleanupCalls > 0, "cleanup must run after MaxDuration timeout")
}

func TestExecutor_ApprovalDenied(t *testing.T) {
	t.Setenv("DISPATCHER_HOME", t.TempDir())
	p := executorTestPlan()
	p.RequiredApprovals = []types.PolicyRequirement{
		{Name: "gpu-approval", Reason: "GPU workloads require approval"},
	}

	mock := newMockAdapter()
	exec := NewExecutor(mock)
	exec.SetApprovalFunc(func(approvals []types.PolicyRequirement) (string, error) {
		assert.Len(t, approvals, 1)
		assert.Equal(t, "gpu-approval", approvals[0].Name)
		return "interactive:test", ErrApprovalDenied
	})
	r := NewRun(p)

	err := exec.Execute(context.Background(), r, io.Discard)
	assert.Error(t, err)
	assert.Equal(t, types.RunStateApprovalDenied, r.GetState())
	assert.Contains(t, err.Error(), "denied")
}

// TestExecutor_FailsClosedWithoutApprover is the regression test for the
// pre-fix bug: when a plan required approvals AND no ApprovalFunc was
// installed, the executor silently proceeded past every policy gate.
// This must NEVER happen — callers either install an approver (terminal
// or auto-approve via `--yes`) or wait for an external `dispatcher approve
// <id>`. With no approver and no external decision, the gate blocks
// indefinitely; we assert that here by using a short ctx deadline.
func TestExecutor_FailsClosedWithoutApprover(t *testing.T) {
	t.Setenv("DISPATCHER_HOME", t.TempDir())

	p := executorTestPlan()
	p.RequiredApprovals = []types.PolicyRequirement{
		{Name: "gpu-approval", Reason: "GPU workloads require approval"},
	}

	mock := newMockAdapter()
	exec := NewExecutor(mock)
	// Deliberately NO SetApprovalFunc. The gate has no in-process approver
	// and nobody is connecting from outside, so Wait will block until ctx
	// expires.
	r := NewRun(p)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := exec.Execute(ctx, r, io.Discard)
	require.Error(t, err)
	assert.Equal(t, types.RunStateApprovalDenied, r.GetState())
	// Critically — the adapter must NOT have been invoked: policy gates
	// stay closed even when the deadline trips.
	assert.False(t, mock.executed,
		"adapter.Execute must not have run when no approval arrived")
}

func TestExecutor_ApprovalGranted(t *testing.T) {
	t.Setenv("DISPATCHER_HOME", t.TempDir())

	p := executorTestPlan()
	p.RequiredApprovals = []types.PolicyRequirement{
		{Name: "cost-approval", Reason: "cost exceeds threshold"},
	}

	mock := newMockAdapter()
	exec := NewExecutor(mock)
	approved := false
	exec.SetApprovalFunc(func(approvals []types.PolicyRequirement) (string, error) {
		approved = true
		return "test", nil
	})
	r := NewRun(p)

	err := exec.Execute(context.Background(), r, io.Discard)
	require.NoError(t, err)
	assert.True(t, approved)
	assert.Equal(t, types.RunStateCompleted, r.GetState())
}

func TestExecutor_ContextCancellation(t *testing.T) {
	mock := newMockAdapter()
	mock.executeErr = fmt.Errorf("context canceled")
	exec := NewExecutor(mock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	r := NewRun(executorTestPlan())
	err := exec.Execute(ctx, r, io.Discard)
	assert.Error(t, err)
}

func TestExecutor_EphemeralLifecycle(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	mock := newMockAdapter()
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, LifecycleEphemeral, r.Lifecycle)
}

func TestExecutor_HandlePersisted(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	mock := newMockAdapter()
	exec := NewExecutor(mock)
	r := NewRun(executorTestPlan())

	err := exec.Execute(context.Background(), r, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, "mock-handle", r.HandleID)
}
