package cloudvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

func sshConfTestPlan(t *testing.T, id string, command []string) *types.Plan {
	t.Helper()
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, ".env"), []byte("SECRET=sshvm\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "main.sh"), []byte("echo hi\n"), 0o644))
	return &types.Plan{
		Metadata: types.PlanMetadata{ID: id},
		Workload: types.WorkloadSpec{
			Name:    "job",
			Source:  types.WorkloadSource{Path: src},
			Command: command,
			Requirements: types.ResourceRequirements{
				Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp"},
			},
		},
	}
}

// cannedVerify returns a verify seam yielding a fixed verdict, so the shared
// SSH-VM orchestration (Azure MAA, AWS SEV-SNP) can be driven without a live TEE
// agent — the attesters themselves are covered in the attest package.
func cannedVerify(res attest.AttestationResult, err error) func(context.Context, *VMInfo, string, types.ConfidentialRequirement) (attest.AttestationResult, error) {
	return func(context.Context, *VMInfo, string, types.ConfidentialRequirement) (attest.AttestationResult, error) {
		return res, err
	}
}

// TestExecuteSSHConfidential_HappyPath drives the shared SSH-VM confidential
// orchestration: provision → start agent → verify → seal source/.env → run →
// sealed result. The VM stays up until Cleanup.
func TestExecuteSSHConfidential_HappyPath(t *testing.T) {
	var got agent.Payload
	stubExchange(t, &got, agent.Result{ExitCode: 0, Stdout: []byte("ran")}, nil)

	provider := NewMockProvider(ProviderAzure)
	deps := sshConfidentialDeps{
		provider:   provider,
		startAgent: func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:  func(context.Context, string) error { return nil },
		verify:     cannedVerify(attest.AttestationResult{Verified: true, Measurement: "pcr-11:abcd", ChannelKey: []byte("channel-key")}, nil),
	}

	state, err := executeSSHConfidential(context.Background(), deps, sshConfTestPlan(t, "run-1", []string{"sh", "main.sh"}), "dispatcher-cvm-job")
	require.NoError(t, err)
	assert.True(t, state.Attestation.Verified)
	assert.Equal(t, "pcr-11:abcd", state.Attestation.Measurement)
	assert.Equal(t, 0, state.Result.ExitCode)
	assert.Equal(t, []byte("SECRET=sshvm\n"), got.DotEnv, "the .env is delivered sealed")
	assert.NotEmpty(t, got.SourceTarGz, "the source is delivered sealed")
	assert.Equal(t, 1, provider.VMCount(), "the VM stays up until Cleanup")
}

// TestExecuteSSHConfidential_ThreadsEnclaveShape confirms the generalized VM shape
// reaches the provider: a Nitro parent requests enclave support + a pinned
// instance type and NO memory-encryption type (the enclave is the TEE, not the
// parent), while the CVM paths keep ConfidentialType.
func TestExecuteSSHConfidential_ThreadsEnclaveShape(t *testing.T) {
	stubExchange(t, nil, agent.Result{ExitCode: 0}, nil)

	provider := NewMockProvider(ProviderAWS)
	deps := sshConfidentialDeps{
		provider:     provider,
		enclave:      true,
		instanceType: "c6a.xlarge",
		startAgent:   func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:    func(context.Context, string) error { return nil },
		verify:       cannedVerify(attest.AttestationResult{Verified: true, Measurement: "pcr0", ChannelKey: []byte("k")}, nil),
	}
	_, err := executeSSHConfidential(context.Background(), deps, sshConfTestPlan(t, "run-enc", []string{"true"}), "dispatcher-nitro-job")
	require.NoError(t, err)
	assert.True(t, provider.LastCreateOpts.EnclaveEnabled, "a Nitro parent must request enclave support")
	assert.Equal(t, "c6a.xlarge", provider.LastCreateOpts.InstanceType, "the parent pins an enclave-capable type")
	assert.Empty(t, provider.LastCreateOpts.ConfidentialType, "the parent is not a memory-encrypted CVM")
}

// TestExecuteSSHConfidential_UnverifiedTearsDown is the security gate: an
// unverified verdict seals and runs nothing and tears the VM down.
func TestExecuteSSHConfidential_UnverifiedTearsDown(t *testing.T) {
	ran := false
	prevExchange := runSealedExchange
	runSealedExchange = func(context.Context, string, []byte, agent.Payload) (agent.Result, error) {
		ran = true
		return agent.Result{}, nil
	}
	t.Cleanup(func() { runSealedExchange = prevExchange })

	provider := NewMockProvider(ProviderAzure)
	deps := sshConfidentialDeps{
		provider:   provider,
		startAgent: func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:  func(context.Context, string) error { return nil },
		verify:     cannedVerify(attest.AttestationResult{Verified: false, Verdict: "measurement mismatch"}, nil),
	}

	_, err := executeSSHConfidential(context.Background(), deps, sshConfTestPlan(t, "run-2", []string{"true"}), "dispatcher-cvm-job")
	require.Error(t, err)
	assert.False(t, ran, "a workload must never run on an unverified TEE")
	assert.Equal(t, 0, provider.VMCount(), "the VM must be torn down on attestation rejection")
}

// TestExecuteSSHConfidential_VerifyErrorTearsDown: a verifier error (not just a
// negative verdict) must also tear the VM down and never seal.
func TestExecuteSSHConfidential_VerifyErrorTearsDown(t *testing.T) {
	provider := NewMockProvider(ProviderAzure)
	deps := sshConfidentialDeps{
		provider:   provider,
		startAgent: func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:  func(context.Context, string) error { return nil },
		verify:     cannedVerify(attest.AttestationResult{}, assertErr("token signature invalid")),
	}

	_, err := executeSSHConfidential(context.Background(), deps, sshConfTestPlan(t, "run-3", []string{"true"}), "dispatcher-cvm-job")
	require.Error(t, err)
	assert.Equal(t, 0, provider.VMCount(), "the VM must be torn down when verification errors")
}
