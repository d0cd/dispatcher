package target

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// A measured-boot profile (nitro/azure-snp) is provider-specific: it must make
// only the matching provider's target feasible, so the plan can't recommend a
// cross-cloud target that would silently route to an unmeasured backend.
func TestCheckFeasibility_ConfidentialProfileBinding(t *testing.T) {
	confTarget := func(id string, types_ []string) types.TargetConfig {
		return types.TargetConfig{
			ID:      id,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{types.WorkloadKindScript},
				Resources: types.ResourceCapability{
					Confidential: types.ConfidentialCapability{Supported: true, Types: types_},
				},
			},
		}
	}
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Requirements: types.ResourceRequirements{
			Confidential: types.ConfidentialRequirement{Required: true, Profile: "nitro"},
		},
	}
	// nitro profile is feasible only on aws-vm.
	assert.True(t, CheckFeasibility(confTarget("aws-vm", []string{"sev-snp"}), w).Feasible)
	assert.False(t, CheckFeasibility(confTarget("azure-vm", []string{"sev-snp"}), w).Feasible,
		"nitro profile must be infeasible on azure-vm")

	// azure-snp profile is feasible only on azure-vm.
	w.Requirements.Confidential.Profile = "azure-snp"
	assert.True(t, CheckFeasibility(confTarget("azure-vm", []string{"sev-snp"}), w).Feasible)
	assert.False(t, CheckFeasibility(confTarget("aws-vm", []string{"sev-snp"}), w).Feasible,
		"azure-snp profile must be infeasible on aws-vm")
}

// A workload pinning a GPU model must be infeasible on a target that supports
// GPUs but not that model — otherwise it becomes the recommendation and fails
// only later as a provisioning refusal.
func TestCheckFeasibility_GPUModel(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindGPUJob,
		Requirements: types.ResourceRequirements{
			GPU: types.GPURequirement{Required: true, Model: "h100"},
		},
	}
	target := types.TargetConfig{
		Enabled: true,
		Capabilities: types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindGPUJob},
			Resources: types.ResourceCapability{
				GPU: types.GPUCapability{Supported: true, Models: []string{"t4", "a100"}},
			},
		},
	}
	res := CheckFeasibility(target, w)
	assert.False(t, res.Feasible, "h100 not in the target's models → infeasible")
	assert.Contains(t, joinReasons(res), "h100")

	// Model offered → feasible.
	target.Capabilities.Resources.GPU.Models = []string{"t4", "a100", "h100"}
	assert.True(t, CheckFeasibility(target, w).Feasible)

	// Case-insensitive: an uppercase model must match a lowercase catalog entry
	// (the pricing layer matches with EqualFold — feasibility must agree).
	w.Requirements.GPU.Model = "H100"
	target.Capabilities.Resources.GPU.Models = []string{"t4", "a100", "h100"}
	assert.True(t, CheckFeasibility(target, w).Feasible, "GPU model match must be case-insensitive")

	// No model pinned → any GPU-capable target is fine.
	w.Requirements.GPU.Model = ""
	target.Capabilities.Resources.GPU.Models = []string{"t4"}
	assert.True(t, CheckFeasibility(target, w).Feasible)
}

// A workload requiring BOTH confidential and GPU must be infeasible everywhere:
// dispatcher's confidential backends provision CPU-only CVMs (no confidential GPU
// SKU exists), so a target advertising GPU and confidential independently would
// otherwise be recommended and then silently drop the GPU requirement at run time.
func TestCheckFeasibility_ConfidentialGPUUnsupported(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindGPUJob,
		Requirements: types.ResourceRequirements{
			GPU:          types.GPURequirement{Required: true, Model: "a100"},
			Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp"},
		},
	}
	target := types.TargetConfig{
		ID:      "aws-vm",
		Enabled: true,
		Capabilities: types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindGPUJob},
			Resources: types.ResourceCapability{
				GPU:          types.GPUCapability{Supported: true, Models: []string{"t4", "a10g", "a100"}},
				Confidential: types.ConfidentialCapability{Supported: true, Types: []string{"sev-snp"}},
			},
		},
	}
	res := CheckFeasibility(target, w)
	assert.False(t, res.Feasible, "confidential + GPU must be infeasible (no confidential GPU backend)")
	assert.Contains(t, joinReasons(res), "confidential")
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

// Hetzner Cloud has no GPU server type (the catalog and rate card both say so),
// so a GPU workload must be infeasible on hetzner-vm — otherwise the planner
// prices it CPU-only and recommends a target that run will refuse to provision.
func TestCheckFeasibility_HetznerRejectsGPU(t *testing.T) {
	registry := NewRegistry()
	registry.LoadBuiltins()

	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindGPUJob,
		Requirements: types.ResourceRequirements{
			GPU: types.GPURequirement{Required: true, Count: 1},
		},
	}

	hetzner, ok := registry.Get("hetzner-vm")
	require.True(t, ok)
	result := CheckFeasibility(hetzner, w)
	assert.False(t, result.Feasible, "hetzner-vm has no GPU SKU and must reject GPU workloads")
	assert.Contains(t, result.Reasons[0], "GPU")
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
	assert.Equal(t, "kubernetes", targets[4].ID)
	assert.Equal(t, "firecracker-vm", targets[5].ID)
	assert.Len(t, targets, 11)
}

func TestRuntimeForTarget(t *testing.T) {
	assert.Equal(t, "local-docker", RuntimeForTarget(types.TargetConfig{Kind: types.TargetKindDocker}))
	assert.Equal(t, "kubernetes-deployment", RuntimeForTarget(types.TargetConfig{Kind: types.TargetKindKubernetes}))
}

// sandbox: true is an isolation requirement — feasible on isolated targets
// (container/vm), infeasible on a process-only target (the documented feature
// must not brick the workload).
func TestCheckFeasibility_Sandbox(t *testing.T) {
	registry := NewRegistry()
	registry.LoadBuiltins()
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Requirements: types.ResourceRequirements{Sandbox: true},
	}

	docker, _ := registry.Get("local-docker")
	assert.True(t, CheckFeasibility(docker, w).Feasible, "container isolation satisfies sandbox")

	fc, ok := registry.Get("firecracker-vm")
	require.True(t, ok)
	assert.True(t, CheckFeasibility(fc, w).Feasible, "vm isolation satisfies sandbox")

	local, _ := registry.Get("local-process")
	res := CheckFeasibility(local, w)
	assert.False(t, res.Feasible, "process-only isolation must not satisfy sandbox")
	assert.Contains(t, joinReasons(res), "sandbox")
}

// An attested confidential run on aws-vm/azure-vm needs the measured profile the
// run path demands (nitro/azure-snp); feasibility must agree or the plan
// recommends a target the run then refuses.
func TestCheckFeasibility_ConfidentialRequiresMeasuredProfile(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Requirements: types.ResourceRequirements{
			Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp"}, // attestation defaults on, no profile
		},
	}
	awsConf := types.TargetConfig{
		ID: "aws-vm", Enabled: true,
		Capabilities: types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindScript},
			Resources:     types.ResourceCapability{Confidential: types.ConfidentialCapability{Supported: true, Types: []string{"sev-snp"}}},
		},
	}
	res := CheckFeasibility(awsConf, w)
	assert.False(t, res.Feasible, "aws-vm confidential without profile:nitro must be infeasible")
	assert.Contains(t, joinReasons(res), "nitro")

	// With profile:nitro it's feasible.
	w.Requirements.Confidential.Profile = "nitro"
	assert.True(t, CheckFeasibility(awsConf, w).Feasible, joinReasons(CheckFeasibility(awsConf, w)))

	// attestation:off (encrypted memory, unverified) needs no profile.
	w.Requirements.Confidential.Profile = ""
	w.Requirements.Confidential.Attestation = "off"
	assert.True(t, CheckFeasibility(awsConf, w).Feasible, "attestation:off needs no measured profile")
}
