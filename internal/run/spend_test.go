package run

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

// ActiveSpend sums the accumulated cost of non-terminal (still-billing) runs so
// `status` can warn about money at risk. Terminal runs are already torn down, so
// they don't count.
func TestActiveSpend(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	active := NewRun(testPlan())
	require.NoError(t, active.Transition(types.RunStatePlanning))
	active.Cost = types.CostEstimate{Value: 0.75, Currency: "USD"}
	_, err := active.Save()
	require.NoError(t, err)

	done := NewRun(testPlan())
	done.MarkTerminal(types.RunStateCompleted)
	done.Cost = types.CostEstimate{Value: 9.00, Currency: "USD"}
	_, err = done.Save()
	require.NoError(t, err)

	total, count := ActiveSpend()
	assert.Equal(t, 1, count, "only the non-terminal run is still billing")
	assert.InDelta(t, 0.75, total, 1e-9)
}

// A zero-cost active run (e.g. a local-process run) isn't a billing risk and
// shouldn't be counted or dilute the warning.
func TestActiveSpend_IgnoresZeroCost(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	free := NewRun(testPlan())
	require.NoError(t, free.Transition(types.RunStatePlanning))
	free.Cost = types.CostEstimate{Value: 0, Currency: "USD"}
	_, err := free.Save()
	require.NoError(t, err)

	total, count := ActiveSpend()
	assert.Equal(t, 0, count)
	assert.Zero(t, total)
}
