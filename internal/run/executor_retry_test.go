package run

import (
	"context"
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
	statusSeq []types.RunState
	idx       int
	failure   adapter.FailureDetails
	execCount int
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
	return m.mockAdapter.Execute(ctx, p)
}

func (m *retryAdapter) FailureDetails(_ *adapter.RunHandle) adapter.FailureDetails {
	return m.failure
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
