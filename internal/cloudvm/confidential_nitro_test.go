package cloudvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/types"
)

// The Nitro adapter must satisfy the full TargetAdapter contract.
var _ adapter.TargetAdapter = (*AWSNitroConfidentialAdapter)(nil)

func TestNewAWSNitroConfidentialAdapter_Defaults(t *testing.T) {
	a := NewAWSNitroConfidentialAdapter(NewMockProvider(ProviderAWS), "/eif", "/proxy", "pcr0hex", "",
		Config{ProviderID: ProviderAWS, SSHUser: "ec2-user"})
	assert.Equal(t, "aws-nitro", a.ID())
	assert.Equal(t, defaultNitroInstanceType, a.instanceType, "an unset instance type defaults to an enclave-capable one")
}

// TestNitroExecute_FailsClosedWithoutEIF: without a pinned EIF/proxy/PCR0 the
// adapter must refuse before provisioning anything.
func TestNitroExecute_FailsClosedWithoutEIF(t *testing.T) {
	provider := NewMockProvider(ProviderAWS)
	a := NewAWSNitroConfidentialAdapter(provider, "", "", "", "", Config{ProviderID: ProviderAWS, SSHUser: "ec2-user"})
	_, err := a.Execute(context.Background(), &types.Plan{
		Metadata: types.PlanMetadata{ID: "r1"},
		Workload: types.WorkloadSpec{Name: "job"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EIF")
	assert.Equal(t, 0, provider.VMCount(), "nothing provisioned when the enclave image isn't pinned")
}

func TestNitroCleanup_TerminatesParent(t *testing.T) {
	provider := NewMockProvider(ProviderAWS)
	// Seed a running VM the enclave parent stands in for.
	vm, err := provider.CreateVM(context.Background(), VMOptions{Name: "p"})
	require.NoError(t, err)
	a := NewAWSNitroConfidentialAdapter(provider, "/eif", "/proxy", "pcr0", "", Config{ProviderID: ProviderAWS})
	h := &adapter.RunHandle{ID: vm.ID, State: &confidentialRunState{Provider: ProviderAWS, VMID: vm.ID}}

	res, err := a.Cleanup(context.Background(), h)
	require.NoError(t, err)
	assert.True(t, res.Success)
	assert.Contains(t, res.ResourcesCleaned, vm.ID)
	assert.Equal(t, 0, provider.VMCount(), "terminating the parent tears down the enclave with it")
}
