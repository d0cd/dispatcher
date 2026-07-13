package planner

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestWithinBudget_UnknownRejected(t *testing.T) {
	// No budget → everything passes.
	assert.True(t, withinBudget(nil, 0))
	assert.True(t, withinBudget(&types.CostEstimate{Value: 0, Confidence: types.ConfidenceUnknown}, 0))

	budget := 0.05
	// Priced within budget passes; over budget fails.
	assert.True(t, withinBudget(&types.CostEstimate{Value: 0.01, Confidence: types.ConfidenceLow}, budget))
	assert.False(t, withinBudget(&types.CostEstimate{Value: 0.10, Confidence: types.ConfidenceLow}, budget))
	// Unknown ($0 placeholder) must NOT pass a budget as if free.
	assert.False(t, withinBudget(&types.CostEstimate{Value: 0, Confidence: types.ConfidenceUnknown}, budget))
	// nil (no estimate) can't be confirmed within a budget.
	assert.False(t, withinBudget(nil, budget))
}

func TestCostLess_UnknownSortsLast(t *testing.T) {
	priced := &types.CostEstimate{Value: 0.10, Confidence: types.ConfidenceLow}
	unknown := &types.CostEstimate{Value: 0, Confidence: types.ConfidenceUnknown}
	assert.True(t, costLess(priced, unknown), "a priced target must outrank a $0 unknown")
	assert.False(t, costLess(unknown, priced))
	assert.True(t, costLess(nil, nil) == false) // stable for equal
}
