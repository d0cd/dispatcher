package cloudvm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/d0cd/dispatcher/internal/types"
)

func TestBuildVMOptions_CarriesSelectedInstanceType(t *testing.T) {
	p := &types.Plan{
		Metadata:    types.PlanMetadata{ID: "run_1"},
		Constraints: types.PlanConstraints{AllowSSHFrom: "203.0.113.4/32"},
		Recommendation: &types.Recommendation{
			EstimatedCost: types.CostEstimate{InstanceType: "cpx41"},
		},
	}

	opts := buildVMOptions(p, "fsn1", "dispatcher-job", "/keys/k.pub", "#cloud-config")

	assert.Equal(t, "cpx41", opts.InstanceType, "the priced instance type must reach provisioning")
	assert.Equal(t, "fsn1", opts.Region)
	assert.Equal(t, "dispatcher-job", opts.Name)
	assert.Equal(t, "/keys/k.pub", opts.SSHKeyPath)
	assert.Equal(t, "#cloud-config", opts.UserData)
	assert.Equal(t, "203.0.113.4/32", opts.AllowSSHFrom)
	assert.Equal(t, "run_1", opts.Tags["dispatcher-run-id"])
	assert.Equal(t, "true", opts.Tags["dispatcher"])
}

// A non-cloud or catalog-less estimate has no instance type; the builder must
// fall back to empty (provider default) rather than panicking on nil.
func TestBuildVMOptions_NilRecommendationYieldsEmptyInstanceType(t *testing.T) {
	p := &types.Plan{Metadata: types.PlanMetadata{ID: "run_2"}}

	opts := buildVMOptions(p, "fsn1", "name", "/k.pub", "ud")

	assert.Empty(t, opts.InstanceType)
}

func TestValidateGPUInstance(t *testing.T) {
	gpuSpec := types.WorkloadSpec{Requirements: types.ResourceRequirements{GPU: types.GPURequirement{Required: true}}}
	cpuSpec := types.WorkloadSpec{}

	// A GPU workload that resolved to no specific instance would otherwise
	// provision the provider's CPU default — refuse it instead.
	assert.Error(t, validateGPUInstance(gpuSpec, ""))
	assert.NoError(t, validateGPUInstance(gpuSpec, "g5.xlarge"))
	assert.NoError(t, validateGPUInstance(cpuSpec, ""))
}
