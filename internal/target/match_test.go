package target

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckFeasibility_Confidential(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Requirements: types.ResourceRequirements{
			Confidential: types.ConfidentialRequirement{Required: true, Type: "tdx"},
		},
	}
	target := types.TargetConfig{
		Enabled: true,
		Capabilities: types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindScript},
		},
	}

	// No confidential support at all → infeasible.
	res := CheckFeasibility(target, w)
	assert.False(t, res.Feasible, "non-confidential target must be infeasible")
	assert.Contains(t, joinReasons(res), "confidential")

	// Confidential, but only offers SEV → a TDX job is still infeasible.
	target.Capabilities.Resources.Confidential = types.ConfidentialCapability{Supported: true, Types: []string{"sev"}}
	res = CheckFeasibility(target, w)
	assert.False(t, res.Feasible, "type mismatch must be infeasible")
	assert.Contains(t, joinReasons(res), "tdx")

	// Offers TDX → feasible.
	target.Capabilities.Resources.Confidential.Types = []string{"sev", "tdx"}
	assert.True(t, CheckFeasibility(target, w).Feasible, CheckFeasibility(target, w).Reasons)

	// type "any" → any confidential-capable target works.
	w.Requirements.Confidential.Type = "any"
	target.Capabilities.Resources.Confidential = types.ConfidentialCapability{Supported: true, Types: []string{"sev"}}
	assert.True(t, CheckFeasibility(target, w).Feasible)
}

func joinReasons(r FeasibilityResult) string {
	out := ""
	for _, s := range r.Reasons {
		out += s + " "
	}
	return out
}

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
}
