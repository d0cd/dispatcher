package cloudvm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/d0cd/dispatcher/internal/types"
)

func confidentialPlan(req types.ConfidentialRequirement) *types.Plan {
	return &types.Plan{
		Metadata: types.PlanMetadata{ID: "r1"},
		Workload: types.WorkloadSpec{
			Requirements: types.ResourceRequirements{Confidential: req},
		},
	}
}

func TestBuildVMOptions_ThreadsConfidentialType(t *testing.T) {
	opts := buildVMOptions(confidentialPlan(types.ConfidentialRequirement{Required: true, Type: "tdx"}),
		"us-central1", "vm", "/k.pub", "")
	assert.Equal(t, "tdx", opts.ConfidentialType)
}

func TestBuildVMOptions_ConfidentialAnyWhenTypeBlank(t *testing.T) {
	opts := buildVMOptions(confidentialPlan(types.ConfidentialRequirement{Required: true}),
		"r", "vm", "/k", "")
	assert.Equal(t, "any", opts.ConfidentialType, "a confidential job with no type resolves to any")
}

func TestBuildVMOptions_NoConfidentialByDefault(t *testing.T) {
	opts := buildVMOptions(confidentialPlan(types.ConfidentialRequirement{}), "r", "vm", "/k", "")
	assert.Equal(t, "", opts.ConfidentialType)
}

func TestGCPConfidentialComputeType(t *testing.T) {
	assert.Equal(t, "SEV", gcpConfidentialComputeType("sev"))
	assert.Equal(t, "SEV_SNP", gcpConfidentialComputeType("sev-snp"))
	assert.Equal(t, "TDX", gcpConfidentialComputeType("tdx"))
	assert.Equal(t, "SEV_SNP", gcpConfidentialComputeType("any"), "any picks AMD SEV-SNP on GCP")
}
