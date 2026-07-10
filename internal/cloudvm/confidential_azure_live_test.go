package cloudvm

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	keys, err := LoadAzureMAAKeys(ctx, maaURL)
	require.NoError(t, err, "the pinned MAA /certs JWKS must load")

	// Attest (a fresh nonce) + verify the live token, binding this run + channel key.
	att := &azureAttester{keys: keys, issuer: maaURL, isReady: true, fetch: endpointMAAFetch(endpoint)}
	res, err := att.Verify(ctx, &VMInfo{}, "", "",
		types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{measurement}})
	require.NoError(t, err)
	require.True(t, res.Verified, res.Verdict)
	require.NotEmpty(t, res.ChannelKey)

	// Seal a payload to the attested key, run inside the TEE, open the sealed result.
	result, err := runSealedExchange(ctx, endpoint, res.ChannelKey, runPayload{
		Command: []string{"sh", "-c", "echo hi from TEE; echo secret=$SECRET"},
		DotEnv:  []byte("SECRET=azure-sealed\n"),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, string(result.Stdout), "hi from TEE")
	assert.Contains(t, string(result.Stdout), "secret=azure-sealed", "the sealed .env reached the workload inside the TEE")
}
