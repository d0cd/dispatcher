package cloudvm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

// TestGolden_AzureLiveExchange drives the FULL Azure confidential path against a
// live SEV-SNP CVM running dispatcher-attest-azure: attest via MAA over the
// untrusted endpoint, verify the real token (pinned /certs keys + nested schema +
// client-payload nonce binding), seal source/.env to the attested channel key,
// run it inside the TEE, and open the sealed result. Gated on the live endpoint.
//
//	DISPATCHER_AZURE_LIVE_ENDPOINT=http://<vm-ip>:8443 \
//	DISPATCHER_MAA_URL=https://sharedeus.eus.attest.azure.net \
//	DISPATCHER_AZURE_LIVE_MEASUREMENT=<hex> \
//	go test ./internal/cloudvm -run TestGolden_AzureLiveExchange -v
func TestGolden_AzureLiveExchange(t *testing.T) {
	endpoint := os.Getenv("DISPATCHER_AZURE_LIVE_ENDPOINT")
	if endpoint == "" {
		t.Skip("set DISPATCHER_AZURE_LIVE_ENDPOINT (+ MAA_URL + MEASUREMENT) to run against a live CVM")
	}
	maaURL := os.Getenv("DISPATCHER_MAA_URL")
	measurement := strings.TrimSpace(os.Getenv("DISPATCHER_AZURE_LIVE_MEASUREMENT"))
	require.NotEmpty(t, maaURL)
	require.NotEmpty(t, measurement)

	ctx := context.Background()
	keys, err := attest.LoadAzureMAAKeys(ctx, maaURL)
	require.NoError(t, err, "the pinned MAA /certs JWKS must load")

	// Attest (a fresh nonce) + verify the live token, binding this run + channel key.
	att := attest.NewAzureAttester(keys, maaURL, endpoint)
	res, err := att.Verify(ctx,
		types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{measurement}})
	require.NoError(t, err)
	require.True(t, res.Verified, res.Verdict)
	require.NotEmpty(t, res.ChannelKey)

	// Seal a payload to the attested key, run inside the TEE, open the sealed result.
	result, err := agent.RunSealedExchange(ctx, endpoint, res.ChannelKey, agent.Payload{
		Command: []string{"sh", "-c", "echo hi from TEE; echo secret=$SECRET"},
		DotEnv:  []byte("SECRET=azure-sealed\n"),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, string(result.Stdout), "hi from TEE")
	assert.Contains(t, string(result.Stdout), "secret=azure-sealed", "the sealed .env reached the workload inside the TEE")
}

// TestGolden_AzureLiveAdapter exercises the FULLY INTEGRATED AzureConfidential
// Adapter against real Azure: provision a SEV-SNP CVM, scp+start the agent, open
// the NSG, MAA-attest, seal source/.env, run inside the TEE, retrieve the sealed
// result, and tear down. Gated on DISPATCHER_AZURE_LIVE_BUILD.
//
//	DISPATCHER_AZURE_LIVE_BUILD=1 DISPATCHER_AZURE_AGENT_BIN=<linux/amd64 binary> \
//	DISPATCHER_AZURE_RG=dispatcher-rg DISPATCHER_AZURE_LOCATION=eastus \
//	DISPATCHER_MAA_URL=https://sharedeus.eus.attest.azure.net \
//	DISPATCHER_AZURE_LIVE_MEASUREMENT=<hex> \
//	go test ./internal/cloudvm -run TestGolden_AzureLiveAdapter -v -timeout 20m
func TestGolden_AzureLiveAdapter(t *testing.T) {
	if os.Getenv("DISPATCHER_AZURE_LIVE_BUILD") == "" {
		t.Skip("set DISPATCHER_AZURE_LIVE_BUILD=1 (+ agent bin/rg/location/maa/measurement) to run the integrated live path")
	}
	agentBin := os.Getenv("DISPATCHER_AZURE_AGENT_BIN")
	maaURL := os.Getenv("DISPATCHER_MAA_URL")
	rg := os.Getenv("DISPATCHER_AZURE_RG")
	location := os.Getenv("DISPATCHER_AZURE_LOCATION")
	measurement := strings.TrimSpace(os.Getenv("DISPATCHER_AZURE_LIVE_MEASUREMENT"))
	require.NotEmpty(t, agentBin)
	require.NotEmpty(t, measurement)

	ctx := context.Background()
	keys, err := attest.LoadAzureMAAKeys(ctx, maaURL)
	require.NoError(t, err)

	a := NewAzureConfidentialAdapter(NewAzureProvider(rg, location), keys, maaURL, maaURL, agentBin,
		Config{ProviderID: ProviderAzure, Region: location, SSHUser: "dispatcher"})

	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, ".env"), []byte("SECRET=integrated\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "hello.txt"), []byte("from-source\n"), 0o644))
	p := &types.Plan{
		Metadata: types.PlanMetadata{ID: "azlive"},
		Workload: types.WorkloadSpec{
			Name: "azlive", Source: types.WorkloadSource{Path: src},
			Command:      []string{"sh", "-c", "echo integrated=$SECRET; cat hello.txt"},
			Requirements: types.ResourceRequirements{Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{measurement}}},
		},
	}

	h, err := a.Execute(ctx, p)
	require.NoError(t, err, "integrated Azure confidential run must succeed")
	t.Cleanup(func() { _, _ = a.Cleanup(context.Background(), h) })

	st := h.State.(*confidentialRunState)
	assert.True(t, st.Attestation.Verified)
	assert.Equal(t, 0, st.Result.ExitCode)
	assert.Contains(t, string(st.Result.Stdout), "integrated=integrated", "the sealed .env reached the TEE")
	assert.Contains(t, string(st.Result.Stdout), "from-source", "the sealed source reached the TEE")

	status, err := a.Status(ctx, h)
	require.NoError(t, err)
	assert.Equal(t, types.RunStateCompleted, status)
}
