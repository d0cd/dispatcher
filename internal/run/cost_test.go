package run

import (
	"sync"
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetCostNoRace exercises the locked cost setter against a concurrent
// reader (ToRecord), the exact interleaving the budget sampler creates during
// teardown. Run with -race: the previous unlocked `r.Cost = live` write would
// be flagged here; setCost holds r.mu and keeps it clean.
func TestSetCostNoRace(t *testing.T) {
	r := NewRun(testPlan())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			r.setCost(types.CostEstimate{Value: float64(i), Currency: "USD"})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = r.ToRecord()
		}
	}()
	wg.Wait()
}

func TestComputeLiveCost_NotStarted(t *testing.T) {
	r := NewRun(testPlan())
	r.Plan.Recommendation = &types.Recommendation{
		Target: "local-docker",
		EstimatedCost: types.CostEstimate{
			Value:      0.0,
			Currency:   "USD",
			Confidence: types.ConfidenceHigh,
		},
	}

	est := r.ComputeLiveCost()
	assert.Equal(t, 0.0, est.Value)
}

func TestComputeLiveCost_RunningJob(t *testing.T) {
	p := testPlan()
	p.Recommendation = &types.Recommendation{
		Target: "kubernetes",
		EstimatedCost: types.CostEstimate{
			Value:      2.0, // $2 for assumed 1h
			Currency:   "USD",
			Confidence: types.ConfidenceMedium,
		},
	}
	p.Workload.DetectedKind = types.WorkloadKindJob

	r := NewRun(p)
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))

	// Simulate 30 minutes of runtime
	r.StartedAt = time.Now().Add(-30 * time.Minute)

	est := r.ComputeLiveCost()
	assert.Equal(t, "USD", est.Currency)
	// 30min of a $2/1h job = ~$1.00
	assert.InDelta(t, 1.0, est.Value, 0.1)
}

func TestComputeLiveCost_CompletedService(t *testing.T) {
	p := testPlan()
	p.Recommendation = &types.Recommendation{
		Target: "kubernetes",
		EstimatedCost: types.CostEstimate{
			Value:      24.0, // $24 for assumed 24h
			Currency:   "USD",
			Confidence: types.ConfidenceMedium,
		},
	}
	p.Workload.DetectedKind = types.WorkloadKindService

	r := NewRun(p)
	r.StartedAt = time.Now().Add(-12 * time.Hour)
	r.FinishedAt = time.Now()

	est := r.ComputeLiveCost()
	// 12h of a $24/24h service = $12
	assert.InDelta(t, 12.0, est.Value, 0.5)
}

func TestFinalizeCost(t *testing.T) {
	p := testPlan()
	p.Recommendation = &types.Recommendation{
		Target: "local-docker",
		EstimatedCost: types.CostEstimate{
			Value:      0.0,
			Currency:   "USD",
			Confidence: types.ConfidenceHigh,
		},
	}

	r := NewRun(p)
	r.StartedAt = time.Now().Add(-5 * time.Minute)
	r.FinishedAt = time.Now()

	r.FinalizeCost()
	assert.Equal(t, "USD", r.Cost.Currency)
}
