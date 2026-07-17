package run

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// retryAdapter drives the transient-retry path: Status returns a fixed sequence
// of states, and it reports a transient failure so ClassifyFailure permits one
// retry. Embeds mockAdapter for the rest of the interface (and to avoid making
// the shared mock a FailureReporter, which would change other tests).
type retryAdapter struct {
	*mockAdapter
	statusSeq       []types.RunState
	idx             int
	failure         adapter.FailureDetails
	execCount       int
	failOnExec      int           // if >0, the Nth Execute returns an error
	lingerRunning   bool          // once statusSeq is exhausted, keep reporting Running (until terminated)
	reprovisionWait time.Duration // the retry's Execute blocks this long (models a slow re-provision)
	cleanedHandles  []string
	terminated      atomic.Bool
	termHandle      string // ID of the handle passed to Terminate
	watchdogMu      sync.Mutex
	watchdogHandles []string
}

func (m *retryAdapter) Status(_ context.Context, _ *adapter.RunHandle) (types.RunState, error) {
	if m.terminated.Load() {
		return types.RunStateExecutionFailed, nil
	}
	if m.idx < len(m.statusSeq) {
		s := m.statusSeq[m.idx]
		m.idx++
		return s, nil
	}
	if m.lingerRunning {
		return types.RunStateRunning, nil
	}
	return types.RunStateCompleted, nil
}

func (m *retryAdapter) Terminate(_ context.Context, h *adapter.RunHandle) error {
	m.termHandle = h.ID
	m.terminated.Store(true)
	return nil
}

// Artifacts returns a single ref named for the handle it was collected from, so
// a test can prove which handle's outputs ended up on the run record.
func (m *retryAdapter) Artifacts(_ context.Context, h *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
	return []adapter.ArtifactRef{{Name: h.ID}}, nil
}

func (m *retryAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	m.execCount++
	if m.failOnExec == m.execCount {
		return nil, fmt.Errorf("re-provision failed")
	}
	if m.execCount > 1 && m.reprovisionWait > 0 {
		time.Sleep(m.reprovisionWait) // model a slow re-provision so the sampler can tick mid-window
	}
	h, err := m.mockAdapter.Execute(ctx, p)
	if h != nil {
		// Distinct id per provisioning so a leaked prior handle is detectable.
		h.ID = fmt.Sprintf("handle-%d", m.execCount)
	}
	return h, err
}

func (m *retryAdapter) Cleanup(ctx context.Context, h *adapter.RunHandle) (*adapter.CleanupResult, error) {
	m.cleanedHandles = append(m.cleanedHandles, h.ID)
	return m.mockAdapter.Cleanup(ctx, h)
}

func (m *retryAdapter) FailureDetails(_ *adapter.RunHandle) adapter.FailureDetails {
	return m.failure
}

func (m *retryAdapter) Reconnect(_ context.Context, handleID string, _ json.RawMessage) (*adapter.RunHandle, error) {
	return &adapter.RunHandle{ID: handleID}, nil
}

func (m *retryAdapter) ExtendWatchdog(_ context.Context, h *adapter.RunHandle, ttl time.Duration) (time.Time, error) {
	m.watchdogMu.Lock()
	m.watchdogHandles = append(m.watchdogHandles, h.ID)
	m.watchdogMu.Unlock()
	return time.Now().Add(ttl), nil
}

func (m *retryAdapter) ListResources(context.Context) ([]adapter.ResourceInfo, error) {
	return nil, nil
}

func (m *retryAdapter) DestroyResource(context.Context, adapter.ResourceInfo) error { return nil }

func (m *retryAdapter) watchdogs() []string {
	m.watchdogMu.Lock()
	defer m.watchdogMu.Unlock()
	return append([]string(nil), m.watchdogHandles...)
}

// When the retry's re-provision Execute fails, the already-cleaned old handle
// must not be cleaned a second time (r.Handle is dropped after the pre-retry
// cleanup) — a second DestroyVM on a non-idempotent provider would spuriously
// fail teardown.
func TestExecutor_TransientRetry_ExecuteFails_NoDoubleClean(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	m := &retryAdapter{
		mockAdapter: newMockAdapter(),
		statusSeq:   []types.RunState{types.RunStateExecutionFailed},
		failure:     adapter.FailureDetails{OOMKilled: true},
		failOnExec:  2, // the retry's re-provision fails
	}
	ex := NewExecutor(m)
	r := NewRun(executorTestPlan())
	r.Plan.Constraints.RetryTransientFailures = true

	require.Error(t, ex.Execute(context.Background(), r, io.Discard))
	// handle-1 was cleaned once (before the retry); it must NOT be cleaned again.
	count := 0
	for _, h := range m.cleanedHandles {
		if h == "handle-1" {
			count++
		}
	}
	assert.Equal(t, 1, count, "the old handle must be cleaned exactly once, not double-destroyed")
}

func TestExecutor_TransientRetrySucceeds(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	m := &retryAdapter{
		mockAdapter: newMockAdapter(),
		statusSeq:   []types.RunState{types.RunStateExecutionFailed, types.RunStateCompleted},
		failure:     adapter.FailureDetails{OOMKilled: true}, // classifies as transient
	}
	ex := NewExecutor(m)
	r := NewRun(executorTestPlan())
	r.Plan.Constraints.RetryTransientFailures = true

	require.NoError(t, ex.Execute(context.Background(), r, io.Discard))
	assert.Equal(t, types.RunStateCompleted, r.GetState())
	assert.Equal(t, 1, r.RetryCount, "retried exactly once")
	assert.Equal(t, 2, m.execCount, "one initial Execute + one retry")
	// The first provisioning's handle must be torn down before the retry
	// provisions a new one — otherwise a cloud VM/Job from the failed attempt
	// leaks and keeps billing.
	assert.Contains(t, m.cleanedHandles, "handle-1", "leaked first handle must be cleaned up on retry")
	assert.Contains(t, m.cleanedHandles, "handle-2", "final handle must be cleaned up")
	assert.Contains(t, m.watchdogs(), "handle-1")
	assert.Contains(t, m.watchdogs(), "handle-2",
		"retry must replace the heartbeat closure so the new VM's watchdog is renewed")
}

// After a transient-failure retry succeeds, the run's artifacts must come from
// the re-provisioned handle (handle-2), not the torn-down first attempt — the
// first VM is gone, so collecting from it would yield stale or empty outputs.
func TestExecutor_TransientRetry_CollectsArtifactsFromNewHandle(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	m := &retryAdapter{
		mockAdapter: newMockAdapter(),
		statusSeq:   []types.RunState{types.RunStateExecutionFailed, types.RunStateCompleted},
		failure:     adapter.FailureDetails{OOMKilled: true},
	}
	ex := NewExecutor(m)
	r := NewRun(executorTestPlan())
	r.Plan.Constraints.RetryTransientFailures = true

	require.NoError(t, ex.Execute(context.Background(), r, io.Discard))
	require.Len(t, r.Artifacts, 1)
	assert.Equal(t, "handle-2", r.Artifacts[0].Name,
		"artifacts must be collected from the re-provisioned handle, not the destroyed first attempt")
}

// The cost sampler must keep enforcing the budget across a transient-failure
// retry: the run stays in Running through the retry, so a budget breach on the
// re-provisioned handle still trips BudgetExceeded and terminates that handle.
func TestExecutor_TransientRetry_BudgetEnforcedOnNewHandle(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prev := SetCostSampleInterval(5 * time.Millisecond)
	defer func() { SetCostSampleInterval(prev) }()
	prevPoll := SetStatusPollInterval(2 * time.Millisecond)
	defer func() { SetStatusPollInterval(prevPoll) }()

	m := &retryAdapter{
		mockAdapter:   newMockAdapter(),
		statusSeq:     []types.RunState{types.RunStateExecutionFailed},
		failure:       adapter.FailureDetails{OOMKilled: true},
		lingerRunning: true, // the re-provisioned handle stays Running so the sampler can trip
	}
	ex := NewExecutor(m)
	r := NewRun(executorTestPlan())
	r.Plan.Constraints.RetryTransientFailures = true
	r.Plan.Constraints.MaxEstimatedCostUSD = 0.0001
	// Backstop: if budget enforcement is broken the lingering handle never
	// terminates, so cap the run so the test fails fast instead of hanging.
	r.Plan.Constraints.MaxDuration = 3 * time.Second
	r.Plan.Recommendation.EstimatedCost = types.CostEstimate{Value: 100, Currency: "USD", Confidence: types.ConfidenceHigh}

	require.Error(t, ex.Execute(context.Background(), r, io.Discard))
	assert.Equal(t, types.RunStateBudgetExceeded, r.GetState(),
		"budget must still be enforced during the retry (run stays Running)")
	assert.Equal(t, "handle-2", m.termHandle,
		"the re-provisioned handle, not the first attempt, must be terminated")
}

// During a transient-failure retry the OLD cost sampler must be stopped before
// the (slow) re-provision, not after. Otherwise a budget breach that lands in
// the re-provision window trips BudgetExceeded on the already-destroyed first
// handle, burns the run's only Running->BudgetExceeded transition, and leaves
// the re-provisioned VM running uncapped. The terminate must hit the NEW handle.
func TestExecutor_TransientRetry_BudgetNotBypassedDuringReprovision(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prev := SetCostSampleInterval(5 * time.Millisecond)
	defer func() { SetCostSampleInterval(prev) }()
	prevPoll := SetStatusPollInterval(2 * time.Millisecond)
	defer func() { SetStatusPollInterval(prevPoll) }()

	m := &retryAdapter{
		mockAdapter:     newMockAdapter(),
		statusSeq:       []types.RunState{types.RunStateExecutionFailed},
		failure:         adapter.FailureDetails{OOMKilled: true},
		lingerRunning:   true,
		reprovisionWait: 120 * time.Millisecond, // sampler ticks many times mid-reprovision
	}
	ex := NewExecutor(m)
	r := NewRun(executorTestPlan())
	r.Plan.Constraints.RetryTransientFailures = true
	r.Plan.Constraints.MaxEstimatedCostUSD = 0.00001 // already over budget by the first tick
	r.Plan.Constraints.MaxDuration = 3 * time.Second
	r.Plan.Recommendation.EstimatedCost = types.CostEstimate{Value: 100, Currency: "USD", Confidence: types.ConfidenceHigh}

	require.Error(t, ex.Execute(context.Background(), r, io.Discard))
	assert.Equal(t, types.RunStateBudgetExceeded, r.GetState())
	assert.Equal(t, "handle-2", m.termHandle,
		"budget kill must terminate the re-provisioned handle, not the destroyed first attempt")
}

func TestExecutor_NoRetryWhenOptInDisabled(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	m := &retryAdapter{
		mockAdapter: newMockAdapter(),
		statusSeq:   []types.RunState{types.RunStateExecutionFailed},
		failure:     adapter.FailureDetails{OOMKilled: true},
	}
	ex := NewExecutor(m)
	r := NewRun(executorTestPlan()) // RetryTransientFailures defaults false

	require.Error(t, ex.Execute(context.Background(), r, io.Discard))
	assert.Equal(t, 0, r.RetryCount)
	assert.Equal(t, 1, m.execCount, "no retry when the opt-in is off")
}

func TestExecutor_StartLongRunning_ExtendsWatchdog(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	d := &mockDurableAdapter{id: "mock"}
	ex := NewExecutor(d)
	r := NewRun(executorTestPlan())
	r.TargetID = "mock"
	r.Handle = &adapter.RunHandle{ID: "h", TargetID: "mock"}

	require.NoError(t, ex.startLongRunning(context.Background(), r, io.Discard))
	assert.False(t, r.LastHeartbeat.IsZero(), "initial heartbeat must be recorded")
	assert.Greater(t, d.lastTTL, time.Duration(0), "initial watchdog TTL must be extended")
}
