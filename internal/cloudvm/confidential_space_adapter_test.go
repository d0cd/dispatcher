package cloudvm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/attest/atls"
	"github.com/d0cd/dispatcher/internal/types"
)

func csTestPlan(t *testing.T, id string, command []string) *types.Plan {
	t.Helper()
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "main.py"), []byte("print(1)"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(src, ".env"), []byte("SECRET=42\n"), 0o600))
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

const csTestDigest = "sha256:cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"

// stubATLSRun replaces the dispatcher-side aTLS run seam. The agent + real
// attestation are covered end-to-end in the attest packages; here we drive only
// the dispatcher-side orchestration. It records the delivered payload and sets the
// attestation verdict the validator would have recorded (attRes). A non-nil err
// models a failed attestation — RunOverATLS aborts before delivering, so nothing
// runs.
func stubATLSRun(t *testing.T, attRes attest.AttestationResult, got *agent.Payload, res agent.Result, err error) {
	t.Helper()
	prev := runOverATLS
	runOverATLS = func(_ context.Context, _ string, validator atls.Validator, p agent.Payload) (agent.Result, error) {
		if err != nil {
			return agent.Result{}, err
		}
		if got != nil {
			*got = p
		}
		if av, ok := validator.(*attest.AttestValidator); ok {
			av.Result = attRes
		}
		return res, nil
	}
	t.Cleanup(func() { runOverATLS = prev })
}

// TestExecuteConfidentialSpace_HappyPath drives the whole dispatcher-side
// orchestration: build image → provision → attest+verify → seal source/.env →
// run → sealed result.
func TestExecuteConfidentialSpace_HappyPath(t *testing.T) {
	var got agent.Payload
	stubATLSRun(t, attest.AttestationResult{Verified: true, Measurement: csTestDigest}, &got, agent.Result{ExitCode: 0, Stdout: []byte("trained")}, nil)

	provider := NewMockProvider(ProviderGCP)
	deps := csDeps{
		provider: provider,
		buildImage: func(context.Context, types.WorkloadSpec) (string, string, error) {
			return "us-docker.pkg.dev/p/r@" + csTestDigest, csTestDigest, nil
		},
		baseURL:   func(*VMInfo) string { return "http://10.0.0.1:8443" },
		waitReady: func(context.Context, string) error { return nil },
	}

	state, err := executeConfidentialSpace(context.Background(), deps, csTestPlan(t, "run-1", []string{"python", "main.py"}))
	require.NoError(t, err)

	assert.True(t, state.Attestation.Verified)
	assert.Equal(t, csTestDigest, state.Attestation.Measurement, "the attested identity is the built image digest")
	assert.Equal(t, 0, state.Result.ExitCode)
	assert.Equal(t, []string{"python", "main.py"}, got.Command)
	assert.Equal(t, []byte("SECRET=42\n"), got.DotEnv, "the .env is delivered sealed")
	assert.NotEmpty(t, got.SourceTarGz, "the source is delivered sealed")
	assert.Equal(t, 1, provider.VMCount(), "the VM stays up until Cleanup")
}

// The GCP Confidential Space path forces a CPU-only SEV SKU (n2d-standard-2), so
// a GPU workload reaching it must be refused before provisioning — never run
// CPU-only on a confidential VM that can't do the job.
func TestExecuteConfidentialSpace_RefusesGPUWorkload(t *testing.T) {
	stubATLSRun(t, attest.AttestationResult{Verified: true}, nil, agent.Result{ExitCode: 0}, nil)

	provider := NewMockProvider(ProviderGCP)
	deps := csDeps{
		provider: provider,
		buildImage: func(context.Context, types.WorkloadSpec) (string, string, error) {
			return "us-docker.pkg.dev/p/r@" + csTestDigest, csTestDigest, nil
		},
		baseURL:   func(*VMInfo) string { return "http://10.0.0.1:8443" },
		waitReady: func(context.Context, string) error { return nil },
	}
	plan := csTestPlan(t, "run-gpu", []string{"true"})
	plan.Workload.Requirements.GPU = types.GPURequirement{Required: true, Model: "a100"}

	_, err := executeConfidentialSpace(context.Background(), deps, plan)
	require.Error(t, err)
	assert.Equal(t, 0, provider.VMCount(), "must refuse before provisioning a CPU-only confidential VM")
}

// TestExecuteConfidentialSpace_UnverifiedTearsDown is the security gate: when
// attestation does not verify, nothing is sealed or run and the VM is torn down.
func TestExecuteConfidentialSpace_UnverifiedTearsDown(t *testing.T) {
	// A real RunOverATLS attests first and returns this error WITHOUT delivering
	// the payload (the no-run-on-unverified-TEE guarantee is proven in the attest
	// packages); here we assert the adapter tears the VM down on that error.
	stubATLSRun(t, attest.AttestationResult{}, nil, agent.Result{}, fmt.Errorf("attestation rejected: digest mismatch"))

	provider := NewMockProvider(ProviderGCP)
	deps := csDeps{
		provider: provider,
		buildImage: func(context.Context, types.WorkloadSpec) (string, string, error) {
			return "ref@" + csTestDigest, csTestDigest, nil
		},
		baseURL:   func(*VMInfo) string { return "http://10.0.0.1:8443" },
		waitReady: func(context.Context, string) error { return nil },
	}

	_, err := executeConfidentialSpace(context.Background(), deps, csTestPlan(t, "run-2", []string{"true"}))
	require.Error(t, err)
	assert.Equal(t, 0, provider.VMCount(), "the VM must be torn down on attestation rejection")
}

// A run that fails after provisioning must reap the agent-port firewall too, not
// just the VM — otherwise every post-provision failure (incl. attestation
// rejection) leaks a per-run firewall rule.
func TestExecuteConfidentialSpace_UnverifiedReapsFirewall(t *testing.T) {
	stubATLSRun(t, attest.AttestationResult{}, nil, agent.Result{}, fmt.Errorf("attestation rejected: digest mismatch"))

	provider := &firewallMockProvider{MockProvider: NewMockProvider(ProviderGCP)}
	deps := csDeps{
		provider: provider,
		buildImage: func(context.Context, types.WorkloadSpec) (string, string, error) {
			return "ref@" + csTestDigest, csTestDigest, nil
		},
		baseURL:    func(*VMInfo) string { return "http://10.0.0.1:8443" },
		waitReady:  func(context.Context, string) error { return nil },
		egressCIDR: func(context.Context) (string, error) { return "1.2.3.4/32", nil },
	}

	_, err := executeConfidentialSpace(context.Background(), deps, csTestPlan(t, "run-fw", []string{"true"}))
	require.Error(t, err)
	assert.Equal(t, 0, provider.VMCount(), "the VM must be torn down")
	assert.NotEmpty(t, provider.deletedFirewall, "the agent firewall must be reaped on a post-provision failure")
}

// TestExecuteConfidentialSpace_BuildFailureNoVM: a failed image build must not
// provision anything.
func TestExecuteConfidentialSpace_BuildFailureNoVM(t *testing.T) {
	provider := NewMockProvider(ProviderGCP)
	deps := csDeps{
		provider: provider,
		buildImage: func(context.Context, types.WorkloadSpec) (string, string, error) {
			return "", "", assertErr("build failed")
		},
		baseURL:   func(*VMInfo) string { return "" },
		waitReady: func(context.Context, string) error { return nil },
	}
	_, err := executeConfidentialSpace(context.Background(), deps, csTestPlan(t, "run-3", []string{"true"}))
	require.Error(t, err)
	assert.Equal(t, 0, provider.VMCount(), "no VM when the image never built")
}

// TestExecuteConfidentialSpace_EgressResolutionFailsClosed: if the egress CIDR
// can't be resolved, the run must abort before provisioning — never fall back to
// an unscoped agent firewall that would let any host race the sealed payload.
func TestExecuteConfidentialSpace_EgressResolutionFailsClosed(t *testing.T) {
	provider := NewMockProvider(ProviderGCP)
	deps := csDeps{
		provider: provider,
		buildImage: func(context.Context, types.WorkloadSpec) (string, string, error) {
			return "ref@" + csTestDigest, csTestDigest, nil
		},
		baseURL:    func(*VMInfo) string { return "http://10.0.0.1:8443" },
		waitReady:  func(context.Context, string) error { return nil },
		egressCIDR: func(context.Context) (string, error) { return "", assertErr("no egress ip") },
	}

	_, err := executeConfidentialSpace(context.Background(), deps, csTestPlan(t, "run-egress", []string{"true"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope confidential agent firewall")
	assert.Equal(t, 0, provider.VMCount(), "no VM may be provisioned when the firewall can't be scoped")
}

type assertErr string

func (e assertErr) Error() string { return string(e) }

// firewallMockProvider is a MockProvider that also implements agentFirewaller, so
// Cleanup's best-effort firewall reap can be asserted.
type firewallMockProvider struct {
	*MockProvider
	deletedFirewall string
}

func (f *firewallMockProvider) deleteAgentFirewall(_ context.Context, name string) error {
	f.deletedFirewall = name
	return nil
}

func TestConfidentialSpaceAdapter_CleanupReapsFirewall(t *testing.T) {
	provider := &firewallMockProvider{MockProvider: NewMockProvider(ProviderGCP)}
	a := NewConfidentialSpaceAdapter(provider, nil, nil, Config{ProviderID: ProviderGCP})
	h := &adapter.RunHandle{ID: "vm-1", State: &confidentialRunState{Provider: ProviderGCP, VMID: "vm-1"}}

	res, err := a.Cleanup(context.Background(), h)
	require.NoError(t, err)
	assert.True(t, res.Success)
	assert.Equal(t, agentFirewallName("vm-1"), provider.deletedFirewall, "Cleanup must reap the per-run agent firewall")
	assert.Contains(t, res.ResourcesCleaned, agentFirewallName("vm-1"))
}
