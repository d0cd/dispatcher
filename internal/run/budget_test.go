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
	terminated     atomic.Bool
	blockExecute   bool          // when set, Execute blocks until its context is canceled (models slow provisioning)
	executeIgnores time.Duration // when >0, Execute sleeps this long ignoring cancel, then returns a handle (models provisioning that completed as the budget tripped)
	cleanupCalls   atomic.Int32
}

func (b *budgetAdapter) ID() string { return "test" }
func (b *budgetAdapter) Validate(context.Context, types.WorkloadSpec) (types.ValidationResult, error) {
	return adapter.DefaultValidationResult(), nil
}
func (b *budgetAdapter) EstimateCost(context.Context, types.WorkloadSpec) (types.CostEstimate, error) {
	return types.CostEstimate{}, nil
}
func (b *budgetAdapter) Prepare(context.Context, *types.Plan) error { return nil }
func (b *budgetAdapter) Execute(ctx context.Context, _ *types.Plan) (*adapter.RunHandle, error) {
	if b.executeIgnores > 0 {
		time.Sleep(b.executeIgnores) // provisioning completes despite the budget cancel
		return &adapter.RunHandle{ID: "h", TargetID: "test"}, nil
	}
	if b.blockExecute {
		<-ctx.Done() // provisioning is still in flight until the context is canceled
		return nil, ctx.Err()
	}
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
	b.cleanupCalls.Add(1)
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

	stop := exec.startCostSampler(context.Background(), r, func() error { return a.Terminate(context.Background(), &adapter.RunHandle{ID: "h"}) }, &bytes.Buffer{})
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

	stop := exec.startCostSampler(context.Background(), r, func() error { return a.Terminate(context.Background(), &adapter.RunHandle{ID: "h"}) }, &cliOut)
	time.Sleep(60 * time.Millisecond)
	stop()

	assert.False(t, a.terminated.Load(), "must not terminate a workload that already finished")
	assert.NotContains(t, cliOut.String(), "terminating", "must not claim a termination that did not happen")
	assert.Contains(t, logbuf.String(), "budget.enforce.skipped", "skipped enforcement must be logged, not silent")
}

// The budget must bound the provisioning/staging phase, not only the running
// workload. A breach while adapter.Execute is still provisioning (no handle
// exists yet) must abort provisioning and end the run in BudgetExceeded — a
// long, pricey staging phase can otherwise run entirely uncapped.
func TestExecutor_BudgetEnforcedDuringProvisioning(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prev := SetCostSampleInterval(5 * time.Millisecond)
	defer func() { SetCostSampleInterval(prev) }()

	a := &budgetAdapter{blockExecute: true}
	exec := NewExecutor(a)
	r := &Run{
		ID:    "run_prov_budget",
		State: types.RunStateCreated,
		Plan: &types.Plan{
			Constraints: types.PlanConstraints{MaxEstimatedCostUSD: 0.00001},
			Recommendation: &types.Recommendation{
				Target:        "test",
				EstimatedCost: types.CostEstimate{Value: 100, Currency: "USD", Confidence: types.ConfidenceHigh},
			},
			Workload: types.WorkloadSpec{Name: "job", DetectedKind: types.WorkloadKindScript},
		},
		Timeline: []PhaseMark{{State: types.RunStateCreated}},
	}

	// Backstop: if the budget can't abort provisioning, the blocking Execute never
	// returns — cap the run context so the test fails fast instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := exec.Execute(ctx, r, io.Discard)
	require.Error(t, err)
	assert.Equal(t, types.RunStateBudgetExceeded, r.GetState(),
		"the budget must trip during provisioning, before any handle exists")
}

// A priced run with no budget must still track spend live so `list` and the
// persisted record reflect real cost (not $0.00) and survive a CLI crash — the
// tracker persists live cost even when there's nothing to enforce.
// The provisioning sampler can trip the budget as Execute is completing (its
// terminate=cancelExec had no handle to kill yet). When Execute then returns a
// real handle, the executor must notice the run is already BudgetExceeded and
// tear the VM down — not proceed into the ephemeral lifecycle and let it run
// uncapped.
func TestExecutor_BudgetTripRacingExecuteSuccess_TearsDown(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prev := SetCostSampleInterval(5 * time.Millisecond)
	defer func() { SetCostSampleInterval(prev) }()

	a := &budgetAdapter{executeIgnores: 120 * time.Millisecond} // budget trips during this window
	exec := NewExecutor(a)
	r := &Run{
		ID:    "run_race_budget",
		State: types.RunStateCreated,
		Plan: &types.Plan{
			Constraints: types.PlanConstraints{MaxEstimatedCostUSD: 0.00001},
			Recommendation: &types.Recommendation{
				Target:        "test",
				EstimatedCost: types.CostEstimate{Value: 100, Currency: "USD", Confidence: types.ConfidenceHigh},
			},
			Workload: types.WorkloadSpec{Name: "job", DetectedKind: types.WorkloadKindScript},
		},
		Timeline: []PhaseMark{{State: types.RunStateCreated}},
	}

	err := exec.Execute(context.Background(), r, io.Discard)
	require.Error(t, err)
	assert.Equal(t, types.RunStateBudgetExceeded, r.GetState())
	assert.Greater(t, a.cleanupCalls.Load(), int32(0), "the just-provisioned VM must be torn down, not left running uncapped")
}

func TestCostSampler_PersistsLiveCostForPricedRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prev := SetCostSampleInterval(5 * time.Millisecond)
	defer func() { SetCostSampleInterval(prev) }()

	a := &budgetAdapter{}
	exec := NewExecutor(a)
	r := &Run{
		ID:    "run_priced_nobudget",
		State: types.RunStateRunning,
		Plan: &types.Plan{
			Constraints: types.PlanConstraints{}, // no budget
			Recommendation: &types.Recommendation{
				Target:        "test",
				EstimatedCost: types.CostEstimate{Value: 100, Currency: "USD", Confidence: types.ConfidenceHigh},
			},
			Workload: types.WorkloadSpec{DetectedKind: types.WorkloadKindScript},
		},
		StartedAt: time.Now().Add(-time.Minute),
	}

	stop := exec.startCostSampler(context.Background(), r, func() error { return nil }, nil)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && r.ComputeLiveCost().Value > 0 {
		if rec, err := LoadRecord(r.ID); err == nil && rec.Cost.Value > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()

	assert.False(t, a.terminated.Load(), "no budget ⇒ nothing to terminate")
	rec, err := LoadRecord(r.ID)
	require.NoError(t, err)
	assert.Greater(t, rec.Cost.Value, 0.0, "live cost must be persisted so list/status show real spend, not $0.00")
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

	stop := exec.startCostSampler(context.Background(), r, func() error { return a.Terminate(context.Background(), &adapter.RunHandle{}) }, nil)
	stop()

	require.False(t, a.terminated.Load(), "no budget means no sampler ⇒ no terminate")
}
