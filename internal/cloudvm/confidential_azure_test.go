package cloudvm

import (
	"context"
	"crypto"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

// maaTokenMinter returns an attestFunc that mints an MAA token binding
// SHA-256(runNonce ‖ channelPub) in client-payload.nonce — the real Azure shape.
func maaTokenMinter(t *testing.T, signKey crypto.Signer) attestFunc {
	return func(_ context.Context, runNonce, channelPub []byte) (string, error) {
		c := validMAAClaims()
		c["x-ms-runtime"].(map[string]any)["client-payload"].(map[string]any)["nonce"] =
			base64.StdEncoding.EncodeToString(maaBindingNonce(runNonce, channelPub))
		return mintJWT(t, "maa1", "RS256", signKey, c), nil
	}
}

func azureTestPlan(t *testing.T, id string, command []string, measurements []string) *types.Plan {
	t.Helper()
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, ".env"), []byte("SECRET=azure\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "main.sh"), []byte("echo hi\n"), 0o644))
	return &types.Plan{
		Metadata: types.PlanMetadata{ID: id},
		Workload: types.WorkloadSpec{
			Name:    "job",
			Source:  types.WorkloadSource{Path: src},
			Command: command,
			Requirements: types.ResourceRequirements{
				Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: measurements},
			},
		},
	}
}

func TestExecuteAzureConfidential_HappyPath(t *testing.T) {
	signKey, keys := maaSigningKey(t)
	var got runPayload
	agent, err := newConfidentialAgent(agentConfig{
		attest: maaTokenMinter(t, signKey),
		runner: func(_ context.Context, p runPayload) runResult {
			got = p
			return runResult{ExitCode: 0, Stdout: []byte("ran")}
		},
	})
	require.NoError(t, err)
	srv := httptest.NewServer(agent.handler())
	t.Cleanup(srv.Close)

	provider := NewMockProvider(ProviderAzure)
	deps := azureDeps{
		provider:   provider,
		keys:       keys,
		issuer:     maaIssuer,
		startAgent: func(context.Context, *VMInfo) (string, error) { return srv.URL, nil },
		waitReady:  func(context.Context, string) error { return nil },
	}

	state, err := executeAzureConfidential(context.Background(), deps,
		azureTestPlan(t, "run-1", []string{"sh", "main.sh"}, []string{maaMeasurement}))
	require.NoError(t, err)
	assert.True(t, state.Attestation.Verified)
	assert.Equal(t, maaMeasurement, state.Attestation.Measurement)
	assert.Equal(t, 0, state.Result.ExitCode)
	assert.Equal(t, []byte("SECRET=azure\n"), got.DotEnv, "the .env is delivered sealed")
	assert.NotEmpty(t, got.SourceTarGz, "the source is delivered sealed")
	assert.Equal(t, 1, provider.VMCount(), "the VM stays up until Cleanup")
}

func TestExecuteAzureConfidential_UnverifiedTearsDown(t *testing.T) {
	signKey, keys := maaSigningKey(t)
	ran := false
	agent, err := newConfidentialAgent(agentConfig{
		attest: maaTokenMinter(t, signKey),
		runner: func(context.Context, runPayload) runResult { ran = true; return runResult{} },
	})
	require.NoError(t, err)
	srv := httptest.NewServer(agent.handler())
	t.Cleanup(srv.Close)

	provider := NewMockProvider(ProviderAzure)
	deps := azureDeps{
		provider:   provider,
		keys:       keys,
		issuer:     maaIssuer,
		startAgent: func(context.Context, *VMInfo) (string, error) { return srv.URL, nil },
		waitReady:  func(context.Context, string) error { return nil },
	}

	// The workload pins a measurement the token does not attest → reject.
	_, err = executeAzureConfidential(context.Background(), deps,
		azureTestPlan(t, "run-2", []string{"true"}, []string{"a-different-measurement"}))
	require.Error(t, err)
	assert.False(t, ran, "a workload must never run on an unverified TEE")
	assert.Equal(t, 0, provider.VMCount(), "the VM must be torn down on attestation rejection")
}
