package run

import (
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoTerminalStateHasOutgoingTransitions ensures validTransitions carries
// no dead entries: Transition() rejects any move out of a terminal state
// before consulting the table, so a terminal key with outgoing edges is
// unreachable by construction.
func TestNoTerminalStateHasOutgoingTransitions(t *testing.T) {
	for from := range validTransitions {
		assert.Falsef(t, from.IsTerminal(),
			"validTransitions has unreachable entry for terminal state %s", from)
	}
}

// TestSetErrorNoOpWhenTerminal guards the cost-cap race: once the sampler has
// set BudgetExceeded (terminal), a later SetError from the main goroutine must
// not relabel it as execution-failed.
func TestSetErrorNoOpWhenTerminal(t *testing.T) {
	r := NewRun(testPlan())
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))
	require.NoError(t, r.Transition(types.RunStateBudgetExceeded))

	r.SetError(types.RunStateExecutionFailed, assert.AnError)

	assert.Equal(t, types.RunStateBudgetExceeded, r.GetState())
	assert.Empty(t, r.Error)
}

func testPlan() *types.Plan {
	return &types.Plan{
		APIVersion: "dispatcher.dev/v1",
		Kind:       "Plan",
		Metadata: types.PlanMetadata{
			ID:        "plan_test",
			CreatedAt: time.Now().UTC(),
			CreatedBy: "test",
		},
		Workload: types.WorkloadSpec{
			Name:         "test",
			DetectedKind: types.WorkloadKindScript,
		},
		Recommendation: &types.Recommendation{
			Target: "local-docker",
		},
	}
}

func TestNewRun(t *testing.T) {
	r := NewRun(testPlan())
	assert.Equal(t, types.RunStateCreated, r.GetState())
	assert.Equal(t, "plan_test", r.PlanID)
	assert.Equal(t, "local-docker", r.TargetID)
}

func TestTransition_HappyPath(t *testing.T) {
	r := NewRun(testPlan())

	transitions := []types.RunState{
		types.RunStatePlanning,
		types.RunStateValidated,
		types.RunStatePreparing,
		types.RunStateRunning,
		types.RunStateCollectingArtifacts,
		types.RunStateReconcilingCost,
		types.RunStateCleaningUp,
		types.RunStateCompleted,
	}

	for _, to := range transitions {
		require.NoError(t, r.Transition(to), "transition to %s failed", to)
	}

	assert.Equal(t, types.RunStateCompleted, r.GetState())
	assert.False(t, r.StartedAt.IsZero())
	assert.False(t, r.FinishedAt.IsZero())
}

func TestTransition_WithApproval(t *testing.T) {
	r := NewRun(testPlan())

	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStateAwaitingApproval))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))
}

func TestTransition_InvalidTransition(t *testing.T) {
	r := NewRun(testPlan())

	// Cannot jump from Created to Running
	err := r.Transition(types.RunStateRunning)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transition")
}

func TestTransition_FromTerminal(t *testing.T) {
	r := NewRun(testPlan())
	r.SetError(types.RunStateExecutionFailed, assert.AnError)

	err := r.Transition(types.RunStateRunning)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "terminal")
}

func TestTransition_FailureStates(t *testing.T) {
	tests := []struct {
		name  string
		setup []types.RunState
		fail  types.RunState
	}{
		{"plan invalid", []types.RunState{types.RunStatePlanning}, types.RunStatePlanInvalid},
		{"approval denied", []types.RunState{types.RunStatePlanning, types.RunStateValidated, types.RunStateAwaitingApproval}, types.RunStateApprovalDenied},
		{"package failed", []types.RunState{types.RunStatePlanning, types.RunStateValidated, types.RunStatePreparing}, types.RunStatePackageFailed},
		{"execution failed", []types.RunState{types.RunStatePlanning, types.RunStateValidated, types.RunStatePreparing, types.RunStateRunning}, types.RunStateExecutionFailed},
		{"cleanup failed", []types.RunState{types.RunStatePlanning, types.RunStateValidated, types.RunStatePreparing, types.RunStateRunning, types.RunStateCollectingArtifacts, types.RunStateReconcilingCost, types.RunStateCleaningUp}, types.RunStateCleanupFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRun(testPlan())
			for _, s := range tt.setup {
				require.NoError(t, r.Transition(s))
			}
			require.NoError(t, r.Transition(tt.fail))
			assert.True(t, r.GetState().IsTerminal())
			assert.True(t, r.GetState().IsFailure())
		})
	}
}

func TestSetError(t *testing.T) {
	r := NewRun(testPlan())
	r.SetError(types.RunStateExecutionFailed, assert.AnError)

	assert.Equal(t, types.RunStateExecutionFailed, r.GetState())
	assert.NotEmpty(t, r.Error)
	assert.False(t, r.FinishedAt.IsZero())
}
