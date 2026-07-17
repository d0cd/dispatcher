package run

import (
	"time"

	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/types"
)

// ComputeLiveCost calculates the estimated cost based on actual elapsed time.
func (r *Run) ComputeLiveCost() types.CostEstimate {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.Plan == nil || r.Plan.Recommendation == nil {
		return types.CostEstimate{Currency: "USD", Confidence: types.ConfidenceUnknown}
	}

	// Get the rate-based estimate for 1 hour
	baseEst := r.Plan.Recommendation.EstimatedCost

	// Compute actual elapsed hours. Clamp negative durations to zero —
	// clock skew (NTP jumping the wall clock backward, FinishedAt being
	// set before StartedAt by some adapter bug) would otherwise produce
	// a negative cost and silently corrupt history.
	var elapsed time.Duration
	if !r.StartedAt.IsZero() {
		if r.FinishedAt.IsZero() {
			elapsed = time.Since(r.StartedAt)
		} else {
			elapsed = r.FinishedAt.Sub(r.StartedAt)
		}
	}
	if elapsed < 0 {
		elapsed = 0
	}

	if elapsed == 0 {
		return baseEst
	}

	elapsedHours := elapsed.Hours()

	// Scale the original estimate proportionally
	// Original estimate assumed a default duration
	assumedHours := cost.DefaultDurationHours
	if r.Plan.Workload.DetectedKind == types.WorkloadKindService {
		assumedHours = 24.0
	}

	if assumedHours == 0 {
		return baseEst
	}

	scaledValue := baseEst.Value * (elapsedHours / assumedHours)
	// Truncate to 4 decimal places so sub-cent runs (cheap cloud VMs for a
	// minute or two) aren't recorded as zero in the persisted history record
	// (which a 2-decimal round would do). The display layer (cli/list.go
	// formatCost) decides how many decimals to actually show.
	scaledValue = float64(int(scaledValue*10000)) / 10000

	return types.CostEstimate{
		Value:      scaledValue,
		Currency:   "USD",
		Confidence: baseEst.Confidence,
		Assumptions: []string{
			"cost scaled from rate card based on actual runtime",
			elapsed.Round(time.Second).String() + " elapsed",
		},
	}
}

// FinalizeCost computes the final cost and stores it on the run. When the plan
// is unavailable (a run reconstructed from a record on stop/force-stop), the
// live cost can't be recomputed — preserve whatever cost was already accrued
// rather than overwriting it with a zero estimate.
func (r *Run) FinalizeCost() {
	r.mu.RLock()
	noPlan := r.Plan == nil || r.Plan.Recommendation == nil
	priorValue := r.Cost.Value
	r.mu.RUnlock()

	if noPlan && priorValue > 0 {
		return
	}
	est := r.ComputeLiveCost()
	r.setCost(est)
}

// setCost stores a cost estimate under the run lock. All writes to r.Cost
// must go through here (or FinalizeCost) so they stay synchronized with the
// locked readers in ToRecord/ComputeLiveCost.
func (r *Run) setCost(est types.CostEstimate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Cost = est
}
