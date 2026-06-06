package target

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckFeasibility_SimpleScript(t *testing.T) {
	registry := NewRegistry()
	registry.LoadBuiltins()

	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Runtime:      types.RuntimePython,
	}

	docker, _ := registry.Get("local-docker")
	result := CheckFeasibility(docker, w)
	assert.True(t, result.Feasible)
}

// CheckFeasibility_KindToCapabilityMapping verifies the E2B/sandbox capability
// branch still functions even though e2b is not a default builtin.
func TestCheckFeasibility_KindToCapabilityMapping(t *testing.T) {
	e2b := types.TargetConfig{
		ID:      "e2b-test",
		Kind:    types.TargetKindE2B,
		Enabled: true,
		Capabilities: types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindSandbox, types.WorkloadKindScript},
			Isolation:     types.IsolationCapability{Levels: []string{"sandbox"}},
		},
	}
	result := CheckFeasibility(e2b, types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Runtime:      types.RuntimePython,
	})
	assert.True(t, result.Feasible)
}

func TestCheckFeasibility_GPUJobRejectsCPUOnly(t *testing.T) {
	registry := NewRegistry()
	registry.LoadBuiltins()

	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindGPUJob,
		Requirements: types.ResourceRequirements{
			GPU: types.GPURequirement{Required: true, Count: 1, Framework: "pytorch"},
		},
	}

	docker, _ := registry.Get("local-docker")
	result := CheckFeasibility(docker, w)
	assert.False(t, result.Feasible)
	assert.Contains(t, result.Reasons[0], "not supported")

	k8s, _ := registry.Get("kubernetes")
	result = CheckFeasibility(k8s, w)
	assert.True(t, result.Feasible)
}

func TestCheckFeasibility_ServiceRejectsE2B(t *testing.T) {
	e2b := types.TargetConfig{
		ID:      "e2b-test",
		Kind:    types.TargetKindE2B,
		Enabled: true,
		Capabilities: types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindSandbox, types.WorkloadKindScript},
		},
	}
	result := CheckFeasibility(e2b, types.WorkloadSpec{
		DetectedKind: types.WorkloadKindService,
		Ports:        []int{8080},
	})
	assert.False(t, result.Feasible)
}

func TestCheckFeasibility_DisabledTarget(t *testing.T) {
	t.Run("disabled target is not feasible", func(t *testing.T) {
		disabled := types.TargetConfig{
			ID:      "test",
			Kind:    types.TargetKindDocker,
			Enabled: false,
		}
		result := CheckFeasibility(disabled, types.WorkloadSpec{DetectedKind: types.WorkloadKindScript})
		assert.False(t, result.Feasible)
		assert.Contains(t, result.Reasons[0], "disabled")
	})
}

func TestRegistryListOrder(t *testing.T) {
	registry := NewRegistry()
	registry.LoadBuiltins()

	targets := registry.List()
	assert.Equal(t, "local-process", targets[0].ID)
	assert.Equal(t, "local-docker", targets[1].ID)
	assert.Equal(t, "lima-vm", targets[2].ID)
	assert.Equal(t, "ssh", targets[3].ID)
	assert.Len(t, targets, 9)
}

func TestRuntimeForTarget(t *testing.T) {
	assert.Equal(t, "local-docker", RuntimeForTarget(types.TargetConfig{Kind: types.TargetKindDocker}))
	assert.Equal(t, "kubernetes-deployment", RuntimeForTarget(types.TargetConfig{Kind: types.TargetKindKubernetes}))
	assert.Equal(t, "managed-sandbox", RuntimeForTarget(types.TargetConfig{Kind: types.TargetKindE2B}))
}
