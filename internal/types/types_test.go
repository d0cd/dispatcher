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
