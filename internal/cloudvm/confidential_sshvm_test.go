package cloudvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

// TestConfidentialVMAdapter_CleanupDestroyFailureSurfacesError: a failed VM
// teardown must be reported (Success=false + the error), not silently swallowed —
// a leaked confidential VM keeps billing and holds the sealed workload.
func TestConfidentialVMAdapter_CleanupDestroyFailureSurfacesError(t *testing.T) {
	provider := NewMockProvider(ProviderAzure)
	provider.DestroyErr = assertErr("destroy refused")
	a := &confidentialVMAdapter{provider: provider}
	h := &adapter.RunHandle{ID: "vm-9", State: &confidentialRunState{Provider: ProviderAzure, VMID: "vm-9"}}

	res, err := a.Cleanup(context.Background(), h)
	require.NoError(t, err)
	assert.False(t, res.Success, "a failed teardown must not report success")
	assert.Contains(t, res.Errors, "destroy refused")
}

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

// cannedValidator supplies the deps a validator; its recorded verdict (Result) is
// set by stubATLSRun (the aTLS run seam), so tests drive the verdict there.
func cannedValidator(types.ConfidentialRequirement) *attest.AttestValidator {
	return &attest.AttestValidator{}
}

// TestExecuteSSHConfidential_HappyPath drives the shared SSH-VM confidential
// orchestration: provision → start agent → verify → seal source/.env → run →
// sealed result. The VM stays up until Cleanup.
func TestExecuteSSHConfidential_HappyPath(t *testing.T) {
	var got agent.Payload
	stubATLSRun(t, attest.AttestationResult{Verified: true, Measurement: "pcr-11:abcd"}, &got, agent.Result{ExitCode: 0, Stdout: []byte("ran")}, nil)

	provider := NewMockProvider(ProviderAzure)
	deps := sshConfidentialDeps{
		provider:   provider,
		startAgent: func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:  func(context.Context, string) error { return nil },
		validator:  cannedValidator,
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

// A confidential SSH-VM (SEV-SNP CVM / Nitro parent) must install the same
// self-destruct watchdog the regular cloud path does: it is the only backstop
// against an unbounded bill if the dispatcher CLI is killed mid-run. The TTL
// must honor the plan's WatchdogTTL.
func TestExecuteSSHConfidential_InstallsWatchdog(t *testing.T) {
	stubATLSRun(t, attest.AttestationResult{Verified: true}, nil, agent.Result{ExitCode: 0}, nil)

	provider := NewMockProvider(ProviderAzure)
	deps := sshConfidentialDeps{
		provider:   provider,
		startAgent: func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:  func(context.Context, string) error { return nil },
		validator:  cannedValidator,
	}
	plan := sshConfTestPlan(t, "run-wd", []string{"true"})
	plan.Constraints.WatchdogTTL = 15 * time.Minute

	_, err := executeSSHConfidential(context.Background(), deps, plan, "dispatcher-cvm-job")
	require.NoError(t, err)
	ud := provider.LastCreateOpts.UserData
	assert.Contains(t, ud, "dispatcher-watchdog.service", "confidential VM must install the self-destruct watchdog backstop")
	assert.Contains(t, ud, "900", "watchdog deadline must honor the plan's WatchdogTTL (15m = 900s)")
}

// Backstop mirroring the plain adapter's validateGPUInstance guard: the
// confidential SSH-VM path forces a CPU-only CVM SKU, so a GPU workload that
// reaches it (e.g. a hand-forced target bypassing feasibility) must be refused
// BEFORE provisioning — never silently run CPU-only on an expensive CVM.
func TestExecuteSSHConfidential_RefusesGPUWorkload(t *testing.T) {
	// Stub the exchange to SUCCEED so the only path to an error (and to VMCount 0)
	// is the GPU guard refusing before provisioning — not a downstream failure
	// whose deferred teardown would coincidentally leave VMCount at 0.
	stubATLSRun(t, attest.AttestationResult{Verified: true}, nil, agent.Result{ExitCode: 0}, nil)

	provider := NewMockProvider(ProviderAWS)
	deps := sshConfidentialDeps{
		provider:     provider,
		confidential: "sev-snp",
		startAgent:   func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:    func(context.Context, string) error { return nil },
		validator:    cannedValidator,
	}
	plan := sshConfTestPlan(t, "run-gpu", []string{"true"})
	plan.Workload.Requirements.GPU = types.GPURequirement{Required: true, Model: "a100"}

	_, err := executeSSHConfidential(context.Background(), deps, plan, "dispatcher-snp-job")
	require.Error(t, err)
	assert.Equal(t, 0, provider.VMCount(), "must refuse before provisioning a CPU-only confidential VM")
}

// TestExecuteSSHConfidential_ThreadsEnclaveShape confirms the generalized VM shape
// reaches the provider: a Nitro parent requests enclave support + a pinned
// instance type and NO memory-encryption type (the enclave is the TEE, not the
// parent), while the CVM paths keep ConfidentialType.
func TestExecuteSSHConfidential_ThreadsEnclaveShape(t *testing.T) {
	stubATLSRun(t, attest.AttestationResult{Verified: true}, nil, agent.Result{ExitCode: 0}, nil)

	provider := NewMockProvider(ProviderAWS)
	deps := sshConfidentialDeps{
		provider:     provider,
		enclave:      true,
		instanceType: "c6a.xlarge",
		startAgent:   func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:    func(context.Context, string) error { return nil },
		validator:    cannedValidator,
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
	// A real RunOverATLS attests first and returns this error WITHOUT delivering
	// (the no-run-on-unverified-TEE guarantee is proven in the attest packages).
	stubATLSRun(t, attest.AttestationResult{}, nil, agent.Result{}, assertErr("measurement mismatch"))

	provider := NewMockProvider(ProviderAzure)
	deps := sshConfidentialDeps{
		provider:   provider,
		startAgent: func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:  func(context.Context, string) error { return nil },
		validator:  cannedValidator,
	}

	_, err := executeSSHConfidential(context.Background(), deps, sshConfTestPlan(t, "run-2", []string{"true"}), "dispatcher-cvm-job")
	require.Error(t, err)
	assert.Equal(t, 0, provider.VMCount(), "the VM must be torn down on attestation rejection")
}

// TestExecuteSSHConfidential_VerifyErrorTearsDown: a verifier error (not just a
// negative verdict) must also tear the VM down and never seal.
func TestExecuteSSHConfidential_VerifyErrorTearsDown(t *testing.T) {
	stubATLSRun(t, attest.AttestationResult{}, nil, agent.Result{}, assertErr("token signature invalid"))
	provider := NewMockProvider(ProviderAzure)
	deps := sshConfidentialDeps{
		provider:   provider,
		startAgent: func(context.Context, *VMInfo) (string, error) { return "http://10.0.0.1:8443", nil },
		waitReady:  func(context.Context, string) error { return nil },
		validator:  cannedValidator,
	}

	_, err := executeSSHConfidential(context.Background(), deps, sshConfTestPlan(t, "run-3", []string{"true"}), "dispatcher-cvm-job")
	require.Error(t, err)
	assert.Equal(t, 0, provider.VMCount(), "the VM must be torn down when verification errors")
}
