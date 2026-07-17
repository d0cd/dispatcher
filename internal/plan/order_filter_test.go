package plan

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func priced(id string, value float64, conf types.Confidence) candidate {
	return candidate{
		target: types.TargetConfig{ID: id},
		cost:   types.CostEstimate{Value: value, Currency: "USD", Confidence: conf},
	}
}

// A pinned target that exceeds the budget must error, not silently reroute to a
// cheaper alternative — the user chose that target deliberately (e.g. for
// isolation) and a quiet substitution defeats the point.
func TestOrderAndFilter_PinnedTargetOverBudgetErrors(t *testing.T) {
	feasible := []candidate{
		priced("aws-vm", 0.50, types.ConfidenceLow), // pinned, over budget
		priced("local", 0.0, types.ConfidenceHigh),  // cheaper alternative
	}
	_, _, err := orderAndFilter(feasible, types.PlanConstraints{
		TargetName:          "aws-vm",
		MaxEstimatedCostUSD: 0.01,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws-vm")
	assert.Contains(t, err.Error(), "budget")
}

// An unknown-cost estimate ($0 placeholder) must not outrank a genuinely-priced
// target when sorting cheapest-first.
func TestSortCandidates_UnknownCostSortsAfterPriced(t *testing.T) {
	c := []candidate{
		priced("unknown-vm", 0.0, types.ConfidenceUnknown),
		priced("priced-vm", 0.10, types.ConfidenceLow),
	}
	sortCandidates(c, types.OptimizeCost)
	assert.Equal(t, "priced-vm", c[0].target.ID, "priced target must outrank an unknown-cost $0")
}

// With a budget set, an unknown-cost target cannot be confirmed within it and
// must be filtered out rather than passing as if it were free.
func TestOrderAndFilter_UnknownCostFailsBudget(t *testing.T) {
	feasible := []candidate{
		priced("unknown-vm", 0.0, types.ConfidenceUnknown),
		priced("priced-vm", 0.005, types.ConfidenceLow),
	}
	kept, _, err := orderAndFilter(feasible, types.PlanConstraints{MaxEstimatedCostUSD: 0.01})
	require.NoError(t, err)
	require.Len(t, kept, 1)
	assert.Equal(t, "priced-vm", kept[0].target.ID, "unknown-cost target must not pass the budget filter")
}

// With no budget, an unknown-cost target is still a valid candidate — it is
// just ordered last.
func TestOrderAndFilter_UnknownCostKeptWhenNoBudget(t *testing.T) {
	feasible := []candidate{
		priced("unknown-vm", 0.0, types.ConfidenceUnknown),
		priced("priced-vm", 0.10, types.ConfidenceLow),
	}
	kept, _, err := orderAndFilter(feasible, types.PlanConstraints{})
	require.NoError(t, err)
	require.Len(t, kept, 2)
	assert.Equal(t, "priced-vm", kept[0].target.ID)
}
