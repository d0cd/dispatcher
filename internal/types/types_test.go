package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunStateIsTerminal(t *testing.T) {
	assert.True(t, RunStateCompleted.IsTerminal())
	assert.True(t, RunStateExecutionFailed.IsTerminal())
	assert.False(t, RunStateRunning.IsTerminal())
	assert.False(t, RunStateCreated.IsTerminal())
}

func TestRunStateIsFailure(t *testing.T) {
	assert.True(t, RunStatePlanInvalid.IsFailure())
	assert.True(t, RunStateCleanupFailed.IsFailure())
	assert.False(t, RunStateCompleted.IsFailure())
	assert.False(t, RunStateRunning.IsFailure())
}

func TestValidationResultIsValid(t *testing.T) {
	valid := ValidationResult{
		Schema:             ValidationPass,
		PackageBuild:       ValidationPass,
		TargetCapabilities: ValidationPass,
		Credentials:        ValidationPass,
		Quota:              ValidationPass,
		Network:            ValidationPass,
		Policy:             ValidationPass,
		CostEstimate:       ValidationPass,
		CleanupPlan:        ValidationPass,
	}
	assert.True(t, valid.IsValid())

	invalid := valid
	invalid.Policy = ValidationFail
	assert.False(t, invalid.IsValid())

	withSkip := valid
	withSkip.Quota = ValidationSkipped
	assert.True(t, withSkip.IsValid())
}

func TestShortID_LengthCharsetAndUniformity(t *testing.T) {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyz"
	inSet := func(r rune) bool {
		for _, c := range chars {
			if c == r {
				return true
			}
		}
		return false
	}
	counts := map[rune]int{}
	const n = 20000
	for i := 0; i < n; i++ {
		id := ShortID()
		assert.Len(t, id, 7)
		for _, r := range id {
			assert.True(t, inSet(r), "unexpected symbol %q", r)
			counts[r]++
		}
	}
	// With rejection sampling the distribution is uniform: no symbol should be
	// wildly over- or under-represented. Expected per-symbol count is 7n/36; a
	// biased byte%36 would push '0'-'3' ~14% above the rest, so a 35% band is a
	// comfortable, non-flaky bound that the old implementation would fail.
	expected := float64(7*n) / float64(len(chars))
	for r, c := range counts {
		ratio := float64(c) / expected
		assert.Greater(t, ratio, 0.65, "symbol %q under-represented (%d)", r, c)
		assert.Less(t, ratio, 1.35, "symbol %q over-represented (%d)", r, c)
	}
}
