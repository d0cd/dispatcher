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

func TestExecute_FailsClosedWhenAttestationRequired(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mock := NewMockProvider(ProviderGCP)
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderGCP, Region: "us-central1"})

	p := &types.Plan{
		Metadata: types.PlanMetadata{ID: "run_cc"},
		Workload: types.WorkloadSpec{
			Name: "secure",
			Requirements: types.ResourceRequirements{
				Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp", Attestation: "required"},
			},
		},
	}
	_, err := a.Execute(context.Background(), p)
	require.Error(t, err, "attestation:required must fail closed until verification exists")
	assert.Contains(t, err.Error(), "attestation")
	assert.Equal(t, 0, mock.VMCount(), "must not provision a VM it can't attest")
}

func TestAttestationPreflight_OffIsAllowed(t *testing.T) {
	w := types.WorkloadSpec{Requirements: types.ResourceRequirements{
		Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp", Attestation: "off"},
	}}
	assert.NoError(t, confidentialAttestationPreflight(w, ProviderGCP), "attestation:off provisions the TEE without verification")
}

func TestGCPConfidentialArgs(t *testing.T) {
	assert.Nil(t, gcpConfidentialArgs(VMOptions{}), "non-confidential VM adds no flags")
	assert.Equal(t,
		[]string{"--confidential-compute-type=SEV_SNP", "--maintenance-policy=TERMINATE"},
		gcpConfidentialArgs(VMOptions{ConfidentialType: "any"}),
		"confidential VMs can't live-migrate, so maintenance must TERMINATE")
	assert.Equal(t,
		[]string{"--confidential-compute-type=TDX", "--maintenance-policy=TERMINATE"},
		gcpConfidentialArgs(VMOptions{ConfidentialType: "tdx"}))
}

func TestAWSConfidentialArgs(t *testing.T) {
	args, err := awsConfidentialArgs(VMOptions{})
	require.NoError(t, err)
	assert.Nil(t, args, "non-confidential VM adds no flags")

	args, err = awsConfidentialArgs(VMOptions{ConfidentialType: "sev-snp"})
	require.NoError(t, err)
	assert.Equal(t, []string{"--cpu-options", "AmdSevSnp=enabled"}, args)

	args, err = awsConfidentialArgs(VMOptions{ConfidentialType: "any"})
	require.NoError(t, err)
	assert.Equal(t, []string{"--cpu-options", "AmdSevSnp=enabled"}, args, "any resolves to AWS's only TEE")

	_, err = awsConfidentialArgs(VMOptions{ConfidentialType: "tdx"})
	require.Error(t, err, "aws has no TDX")
	assert.Contains(t, err.Error(), "sev-snp")
}

func TestAzureConfidentialArgs(t *testing.T) {
	args, err := azureConfidentialArgs(VMOptions{})
	require.NoError(t, err)
	assert.Nil(t, args, "non-confidential VM adds no flags")

	args, err = azureConfidentialArgs(VMOptions{ConfidentialType: "sev-snp"})
	require.NoError(t, err)
	assert.Equal(t,
		[]string{"--security-type", "ConfidentialVM", "--enable-vtpm", "true",
			"--enable-secure-boot", "true", "--os-disk-security-encryption-type", "VMGuestStateOnly"},
		args)

	args, err = azureConfidentialArgs(VMOptions{ConfidentialType: "tdx"})
	require.NoError(t, err)
	assert.Equal(t, "ConfidentialVM", args[1], "tdx uses the same type-agnostic create flag")

	_, err = azureConfidentialArgs(VMOptions{ConfidentialType: "sev"})
	require.Error(t, err, "azure has no plain-sev offering")
	assert.Contains(t, err.Error(), "sev")
}

func TestGCPConfidentialComputeType(t *testing.T) {
	assert.Equal(t, "SEV", gcpConfidentialComputeType("sev"))
	assert.Equal(t, "SEV_SNP", gcpConfidentialComputeType("sev-snp"))
	assert.Equal(t, "TDX", gcpConfidentialComputeType("tdx"))
	assert.Equal(t, "SEV_SNP", gcpConfidentialComputeType("any"), "any picks AMD SEV-SNP on GCP")
}
