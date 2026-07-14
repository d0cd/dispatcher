package cloudvm

import (
	"context"
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
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

// stubCSVerify replaces the CS attester seam with a canned verdict and restores
// it after the test. The agent + real attestation are covered end-to-end in the
// attest package; here we drive only the dispatcher-side orchestration.
func stubCSVerify(t *testing.T, res attest.AttestationResult, err error) {
	t.Helper()
	prev := csVerify
	csVerify = func(context.Context, map[string]crypto.PublicKey, string, types.ConfidentialRequirement) (attest.AttestationResult, error) {
		return res, err
	}
	t.Cleanup(func() { csVerify = prev })
}

// stubExchange replaces the sealed-exchange seam and records the payload it was
// handed, so tests can assert what dispatcher sealed and shipped.
func stubExchange(t *testing.T, got *agent.Payload, res agent.Result, err error) {
	t.Helper()
	prev := runSealedExchange
	runSealedExchange = func(_ context.Context, _ string, _ []byte, p agent.Payload) (agent.Result, error) {
		if got != nil {
			*got = p
		}
		return res, err
	}
	t.Cleanup(func() { runSealedExchange = prev })
}

// TestExecuteConfidentialSpace_HappyPath drives the whole dispatcher-side
// orchestration: build image → provision → attest+verify → seal source/.env →
// run → sealed result.
func TestExecuteConfidentialSpace_HappyPath(t *testing.T) {
	stubCSVerify(t, attest.AttestationResult{Verified: true, Measurement: csTestDigest, ChannelKey: []byte("channel-key")}, nil)
	var got agent.Payload
	stubExchange(t, &got, agent.Result{ExitCode: 0, Stdout: []byte("trained")}, nil)

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

// TestExecuteConfidentialSpace_UnverifiedTearsDown is the security gate: when
// attestation does not verify, nothing is sealed or run and the VM is torn down.
func TestExecuteConfidentialSpace_UnverifiedTearsDown(t *testing.T) {
	stubCSVerify(t, attest.AttestationResult{Verified: false, Verdict: "digest mismatch"}, nil)
	ran := false
	prevExchange := runSealedExchange
	runSealedExchange = func(context.Context, string, []byte, agent.Payload) (agent.Result, error) {
		ran = true
		return agent.Result{}, nil
	}
	t.Cleanup(func() { runSealedExchange = prevExchange })

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
	assert.False(t, ran, "a workload must never run on an unverified TEE")
	assert.Equal(t, 0, provider.VMCount(), "the VM must be torn down on attestation rejection")
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
