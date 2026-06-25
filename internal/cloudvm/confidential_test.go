package cloudvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

func TestAWSCreateVM_RejectsNonSevSnpConfidential(t *testing.T) {
	_, err := NewAWSProvider("us-east-2").CreateVM(context.Background(),
		VMOptions{Name: "x", ConfidentialType: "tdx"})
	require.Error(t, err, "aws has no TDX; must reject before launching")
	assert.Contains(t, err.Error(), "sev-snp")
}

func TestAzureCreateVM_RejectsPlainSevConfidential(t *testing.T) {
	_, err := NewAzureProvider("rg", "eastus").CreateVM(context.Background(),
		VMOptions{Name: "x", ConfidentialType: "sev"})
	require.Error(t, err, "azure confidential is sev-snp/tdx by SKU, not plain sev")
	assert.Contains(t, err.Error(), "sev")
}

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
