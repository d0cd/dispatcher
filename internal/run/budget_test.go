package run

import (
	"bytes"
	"context"
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

type budgetAdapter struct {
	terminated atomic.Bool
}

func (b *budgetAdapter) ID() string { return "test" }
func (b *budgetAdapter) Validate(context.Context, types.WorkloadSpec) (types.ValidationResult, error) {
	return adapter.DefaultValidationResult(), nil
}
func (b *budgetAdapter) EstimateCost(context.Context, types.WorkloadSpec) (types.CostEstimate, error) {
	return types.CostEstimate{}, nil
}
func (b *budgetAdapter) Prepare(context.Context, *types.Plan) error { return nil }
func (b *budgetAdapter) Execute(context.Context, *types.Plan) (*adapter.RunHandle, error) {
	return &adapter.RunHandle{ID: "h", TargetID: "test"}, nil
}
func (b *budgetAdapter) Status(context.Context, *adapter.RunHandle) (types.RunState, error) {
	return types.RunStateRunning, nil
}
func (b *budgetAdapter) Logs(context.Context, *adapter.RunHandle, io.Writer) error { return nil }
func (b *budgetAdapter) Artifacts(context.Context, *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
	return nil, nil
}
func (b *budgetAdapter) Terminate(context.Context, *adapter.RunHandle) error {
	b.terminated.Store(true)
	return nil
}
func (b *budgetAdapter) Cleanup(context.Context, *adapter.RunHandle) (*adapter.CleanupResult, error) {
	return &adapter.CleanupResult{Success: true}, nil
}

// Sampler must call Terminate and transition to BudgetExceeded when live cost
// climbs past the user-supplied --max-cost budget.
func TestCostSampler_TerminatesWhenBudgetExceeded(t *testing.T) {
	prev := SetCostSampleInterval(20 * time.Millisecond)

	defer func() { SetCostSampleInterval(prev) }()

	a := &budgetAdapter{}
	exec := NewExecutor(a)

	r := &Run{
		ID:    "run_budget",
		State: types.RunStateRunning,
		Plan: &types.Plan{
			Constraints: types.PlanConstraints{MaxEstimatedCostUSD: 0.01},
			Recommendation: &types.Recommendation{
				Target:        "test",
				EstimatedCost: types.CostEstimate{Value: 100, Currency: "USD", Confidence: types.ConfidenceHigh},
			},
			Workload: types.WorkloadSpec{DetectedKind: types.WorkloadKindScript},
		},
		StartedAt: time.Now().Add(-time.Minute),
	}

	stop := exec.startCostSampler(context.Background(), r, &adapter.RunHandle{ID: "h"}, &bytes.Buffer{})
	defer stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.terminated.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	assert.True(t, a.terminated.Load(), "sampler must call Terminate when budget is breached")
	assert.Equal(t, types.RunStateBudgetExceeded, r.GetState())
}

// When the workload finishes on its own in the same tick window (the run has
// already left Running), the sampler must not claim a termination it didn't
// perform, and must log that enforcement was skipped rather than doing so
// silently.
func TestCostSampler_SkipsEnforcementAfterWorkloadDone(t *testing.T) {
	prev := SetCostSampleInterval(5 * time.Millisecond)
	defer func() { SetCostSampleInterval(prev) }()

	var logbuf bytes.Buffer
	dlog.SetOutput(&logbuf)
	defer dlog.SetOutput(io.Discard)

	a := &budgetAdapter{}
	exec := NewExecutor(a)
	var cliOut bytes.Buffer

	r := &Run{
		ID:    "run_race",
		State: types.RunStateCollectingArtifacts, // already left Running
		Plan: &types.Plan{
			Constraints: types.PlanConstraints{MaxEstimatedCostUSD: 0.01},
			Recommendation: &types.Recommendation{
				Target:        "test",
				EstimatedCost: types.CostEstimate{Value: 100, Currency: "USD", Confidence: types.ConfidenceHigh},
			},
			Workload: types.WorkloadSpec{DetectedKind: types.WorkloadKindScript},
		},
		StartedAt: time.Now().Add(-time.Minute),
	}

	stop := exec.startCostSampler(context.Background(), r, &adapter.RunHandle{ID: "h"}, &cliOut)
	time.Sleep(60 * time.Millisecond)
	stop()

	assert.False(t, a.terminated.Load(), "must not terminate a workload that already finished")
	assert.NotContains(t, cliOut.String(), "terminating", "must not claim a termination that did not happen")
	assert.Contains(t, logbuf.String(), "budget.enforce.skipped", "skipped enforcement must be logged, not silent")
}

func TestCostSampler_NoBudgetNoSampler(t *testing.T) {
	prev := SetCostSampleInterval(20 * time.Millisecond)

	defer func() { SetCostSampleInterval(prev) }()

	a := &budgetAdapter{}
	exec := NewExecutor(a)
	r := &Run{
		ID:    "run_nobudget",
		State: types.RunStateRunning,
		Plan: &types.Plan{
			Constraints:    types.PlanConstraints{},
			Recommendation: &types.Recommendation{Target: "test"},
		},
	}

	stop := exec.startCostSampler(context.Background(), r, &adapter.RunHandle{}, nil)
	stop()

	require.False(t, a.terminated.Load(), "no budget means no sampler ⇒ no terminate")
}
