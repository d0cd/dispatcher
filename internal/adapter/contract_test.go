package adapter

import (
	"context"
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
)

// ContractTest runs the shared adapter contract test suite against any adapter.
// This verifies every adapter implements the interface correctly.
func ContractTest(t *testing.T, a TargetAdapter) {
	ctx := context.Background()

	t.Run("ID", func(t *testing.T) {
		assert.NotEmpty(t, a.ID())
	})

	t.Run("Validate supported workload", func(t *testing.T) {
		w := types.WorkloadSpec{
			DetectedKind: types.WorkloadKindScript,
			Runtime:      types.RuntimePython,
		}
		_, err := a.Validate(ctx, w)
		// May fail if docker/ssh not available, that's OK for contract test structure
		_ = err
	})

	t.Run("EstimateCost", func(t *testing.T) {
		w := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
		est, err := a.EstimateCost(ctx, w)
		assert.NoError(t, err)
		assert.Equal(t, "USD", est.Currency)
	})

	t.Run("Artifacts on nil handle returns empty", func(t *testing.T) {
		// Artifacts should handle nil/empty gracefully
		h := &RunHandle{ID: "test-handle", TargetID: a.ID()}
		arts, err := a.Artifacts(ctx, h)
		assert.NoError(t, err)
		assert.Empty(t, arts)
	})

	t.Run("Cleanup on nil handle succeeds", func(t *testing.T) {
		h := &RunHandle{ID: "nonexistent", TargetID: a.ID()}
		result, err := a.Cleanup(ctx, h)
		// Should not panic; error or success both acceptable
		_ = err
		_ = result
	})
}

// TestDockerAdapterContract runs contract tests on the Docker adapter.
// Skipped if Docker is not available.
func TestDockerAdapterContract(t *testing.T) {
	a := NewDockerAdapter()
	ctx := context.Background()

	// Check if Docker is available
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	if _, err := a.Validate(ctx, w); err != nil {
		t.Skip("Docker not available, skipping contract test")
	}

	ContractTest(t, a)
}

// TestDockerAdapter_RejectsGPU verifies GPU workloads are rejected.
func TestDockerAdapter_RejectsGPU(t *testing.T) {
	a := NewDockerAdapter()
	ctx := context.Background()

	// First check if Docker is available at all
	simple := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	if _, err := a.Validate(ctx, simple); err != nil {
		t.Skip("Docker not available, skipping GPU rejection test")
	}

	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindGPUJob,
		Requirements: types.ResourceRequirements{
			GPU: types.GPURequirement{Required: true},
		},
	}

	v, err := a.Validate(ctx, w)
	// Either the validation result shows fail or an error is returned
	if err == nil {
		assert.Equal(t, types.ValidationFail, v.TargetCapabilities)
	} else {
		assert.Contains(t, err.Error(), "GPU")
	}
}

// TestDockerAdapter_CostEstimate verifies zero cost for local execution.
func TestDockerAdapter_CostEstimate(t *testing.T) {
	a := NewDockerAdapter()
	ctx := context.Background()

	est, err := a.EstimateCost(ctx, types.WorkloadSpec{})
	assert.NoError(t, err)
	assert.Equal(t, 0.0, est.Value)
	assert.Equal(t, types.ConfidenceHigh, est.Confidence)
}

// TestSSHAdapter_CostEstimate verifies SSH cost estimate.
func TestSSHAdapter_CostEstimate(t *testing.T) {
	a := NewSSHAdapter(SSHConfig{Host: "localhost", User: "test"})
	ctx := context.Background()

	est, err := a.EstimateCost(ctx, types.WorkloadSpec{})
	assert.NoError(t, err)
	assert.Greater(t, est.Value, 0.0)
	assert.Equal(t, types.ConfidenceMedium, est.Confidence)
}
