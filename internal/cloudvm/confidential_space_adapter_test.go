package cloudvm

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
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

// TestExecuteConfidentialSpace_HappyPath drives the whole dispatcher-side
// orchestration against a real in-TEE agent (fake runner): build image → provision
// → attest+verify → seal source/.env → run → sealed result.
func TestExecuteConfidentialSpace_HappyPath(t *testing.T) {
	signKey, keys := maaSigningKey(t)
	var got runPayload
	agent, err := newConfidentialAgent(agentConfig{
		attest: tokenMinter(t, signKey),
		runner: func(_ context.Context, p runPayload) runResult {
			got = p
			return runResult{ExitCode: 0, Stdout: []byte("trained")}
		},
	})
	require.NoError(t, err)
	srv := httptest.NewServer(agent.handler())
	t.Cleanup(srv.Close)

	provider := NewMockProvider(ProviderGCP)
	deps := csDeps{
		provider: provider,
		keys:     keys,
		buildImage: func(context.Context, types.WorkloadSpec) (string, string, error) {
			return "us-docker.pkg.dev/p/r@" + csDigest, csDigest, nil
		},
		baseURL:   func(*VMInfo) string { return srv.URL },
		waitReady: func(context.Context, string) error { return nil },
	}

	state, err := executeConfidentialSpace(context.Background(), deps, csTestPlan(t, "run-1", []string{"python", "main.py"}))
	require.NoError(t, err)

	assert.True(t, state.Attestation.Verified)
	assert.Equal(t, csDigest, state.Attestation.Measurement, "the attested identity is the built image digest")
	assert.Equal(t, 0, state.Result.ExitCode)
	assert.Equal(t, []string{"python", "main.py"}, got.Command)
	assert.Equal(t, []byte("SECRET=42\n"), got.DotEnv, "the .env is delivered sealed")
	assert.NotEmpty(t, got.SourceTarGz, "the source is delivered sealed")
	assert.Equal(t, 1, provider.VMCount(), "the VM stays up until Cleanup")
}

// TestExecuteConfidentialSpace_UnverifiedTearsDown is the security gate: when
// attestation does not verify (here the built image digest isn't what the token
// attests), nothing is sealed or run and the VM is torn down.
func TestExecuteConfidentialSpace_UnverifiedTearsDown(t *testing.T) {
	signKey, keys := maaSigningKey(t)
	ran := false
	agent, err := newConfidentialAgent(agentConfig{
		attest: tokenMinter(t, signKey),
		runner: func(context.Context, runPayload) runResult { ran = true; return runResult{} },
	})
	require.NoError(t, err)
	srv := httptest.NewServer(agent.handler())
	t.Cleanup(srv.Close)

	provider := NewMockProvider(ProviderGCP)
	deps := csDeps{
		provider: provider,
		keys:     keys,
		buildImage: func(context.Context, types.WorkloadSpec) (string, string, error) {
			return "ref@sha256:deadbeef", "sha256:deadbeef", nil // not what the token attests
		},
		baseURL:   func(*VMInfo) string { return srv.URL },
		waitReady: func(context.Context, string) error { return nil },
	}

	_, err = executeConfidentialSpace(context.Background(), deps, csTestPlan(t, "run-2", []string{"true"}))
	require.Error(t, err)
	assert.False(t, ran, "a workload must never run on an unverified TEE")
	assert.Equal(t, 0, provider.VMCount(), "the VM must be torn down on attestation rejection")
}

// TestExecuteConfidentialSpace_BuildFailureNoVM: a failed image build must not
// provision anything.
func TestExecuteConfidentialSpace_BuildFailureNoVM(t *testing.T) {
	_, keys := maaSigningKey(t)
	provider := NewMockProvider(ProviderGCP)
	deps := csDeps{
		provider: provider,
		keys:     keys,
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
	h := &adapter.RunHandle{ID: "vm-1", State: &csRunState{Provider: ProviderGCP, VMID: "vm-1"}}

	res, err := a.Cleanup(context.Background(), h)
	require.NoError(t, err)
	assert.True(t, res.Success)
	assert.Equal(t, agentFirewallName("vm-1"), provider.deletedFirewall, "Cleanup must reap the per-run agent firewall")
	assert.Contains(t, res.ResourcesCleaned, agentFirewallName("vm-1"))
}
