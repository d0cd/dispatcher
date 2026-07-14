package run

import (
	"context"
	"fmt"
	"io"
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
	statusSeq      []types.RunState
	idx            int
	failure        adapter.FailureDetails
	execCount      int
	failOnExec     int // if >0, the Nth Execute returns an error
	cleanedHandles []string
}

func (m *retryAdapter) Status(_ context.Context, _ *adapter.RunHandle) (types.RunState, error) {
	if m.idx < len(m.statusSeq) {
		s := m.statusSeq[m.idx]
		m.idx++
		return s, nil
	}
	return types.RunStateCompleted, nil
}

func (m *retryAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	m.execCount++
	if m.failOnExec == m.execCount {
		return nil, fmt.Errorf("re-provision failed")
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
