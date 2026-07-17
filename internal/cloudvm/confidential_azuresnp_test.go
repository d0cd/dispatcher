package cloudvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

var _ adapter.TargetAdapter = (*AzureSNPConfidentialAdapter)(nil)

func TestNewAzureSNPConfidentialAdapter_ID(t *testing.T) {
	a := NewAzureSNPConfidentialAdapter(NewMockProvider(ProviderAzure), "/img", map[int]string{11: "abc"},
		Config{ProviderID: ProviderAzure, SSHUser: "dispatcher"})
	assert.Equal(t, "azure-snp", a.ID())
}

// TestAzureSNPExecute_FailsClosedWithoutImage: without a pinned measured image +
// PCR11 the adapter must refuse before provisioning.
func TestAzureSNPExecute_FailsClosedWithoutImage(t *testing.T) {
	provider := NewMockProvider(ProviderAzure)
	a := NewAzureSNPConfidentialAdapter(provider, "", nil, Config{ProviderID: ProviderAzure, SSHUser: "dispatcher"})
	_, err := a.Execute(context.Background(), &types.Plan{
		Metadata: types.PlanMetadata{ID: "r1"},
		Workload: types.WorkloadSpec{Name: "job"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "measured")
	assert.Equal(t, 0, provider.VMCount(), "nothing provisioned without a pinned measured image")
}

func TestAzureSNPCleanup_DestroysVM(t *testing.T) {
	provider := NewMockProvider(ProviderAzure)
	vm, err := provider.CreateVM(context.Background(), VMOptions{Name: "cvm"})
	require.NoError(t, err)
	a := NewAzureSNPConfidentialAdapter(provider, "/img", map[int]string{11: "abc"}, Config{ProviderID: ProviderAzure})
	h := &adapter.RunHandle{ID: vm.ID, State: &confidentialRunState{Provider: ProviderAzure, VMID: vm.ID}}

	res, err := a.Cleanup(context.Background(), h)
	require.NoError(t, err)
	assert.True(t, res.Success)
	assert.Equal(t, 0, provider.VMCount())
}

// TestExecuteSSHConfidential_ThreadsSecureBootOff confirms the Azure measured path
// requests Secure Boot off (the unsigned custom UKI image needs it), verified
// against the provider's recorded VMOptions.
func TestExecuteSSHConfidential_ThreadsSecureBootOff(t *testing.T) {
	stubATLSRun(t, attest.AttestationResult{Verified: true}, nil, agent.Result{ExitCode: 0}, nil)
	provider := NewMockProvider(ProviderAzure)
	deps := sshConfidentialDeps{
		provider:      provider,
		confidential:  "sev-snp",
		secureBootOff: true,
		image:         "/gallery/measured",
		startAgent:    func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:     func(context.Context, string) error { return nil },
		validator:     cannedValidator,
	}
	_, err := executeSSHConfidential(context.Background(), deps, sshConfTestPlan(t, "run-snp", []string{"true"}), "dispatcher-azsnp-job")
	require.NoError(t, err)
	assert.True(t, provider.LastCreateOpts.SecureBootDisabled, "the measured image boots with Secure Boot off")
	assert.Equal(t, "sev-snp", provider.LastCreateOpts.ConfidentialType, "still a memory-encrypted CVM")
	assert.Equal(t, "/gallery/measured", provider.LastCreateOpts.Image)
}
