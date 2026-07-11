package attest

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

// TestGolden_NitroLiveExchange drives the full AWS Nitro path against a live
// enclave running dispatcher-attest-nitro, reached via dispatcher-nitro-proxy on
// the parent: fetch + verify the real Nitro attestation document (chain to the
// pinned Root-G1 + COSE signature + nonce + pinned PCR0), seal source/.env to the
// doc's public_key, run inside the enclave, and open the sealed result. Gated on
// the live endpoint so CI stays offline.
//
//	DISPATCHER_NITRO_LIVE_ENDPOINT=http://<parent-ip>:8443 \
//	DISPATCHER_NITRO_LIVE_PCR0=<pcr0 hex from build-eif.sh> \
//	go test ./internal/attest -run TestGolden_NitroLiveExchange -v
func TestGolden_NitroLiveExchange(t *testing.T) {
	endpoint := os.Getenv("DISPATCHER_NITRO_LIVE_ENDPOINT")
	if endpoint == "" {
		t.Skip("set DISPATCHER_NITRO_LIVE_ENDPOINT (+ DISPATCHER_NITRO_LIVE_PCR0) to run against a live enclave")
	}
	pcr0 := strings.TrimSpace(os.Getenv("DISPATCHER_NITRO_LIVE_PCR0"))
	require.NotEmpty(t, pcr0, "DISPATCHER_NITRO_LIVE_PCR0 is required")

	ctx := context.Background()
	att := NewAWSNitroAttester(map[int]string{0: pcr0}, endpoint)
	res, err := att.Verify(ctx, types.ConfidentialRequirement{Required: true, Type: "nitro"})
	require.NoError(t, err)
	require.True(t, res.Verified, res.Verdict)
	require.NotEmpty(t, res.ChannelKey, "a verified result carries the bound channel key to seal to")
	assert.Equal(t, pcr0, res.Measurement, "the attested measurement is the pinned enclave PCR0")

	result, err := agent.RunSealedExchange(ctx, endpoint, res.ChannelKey, agent.Payload{
		Command: []string{"sh", "-c", "echo hi from enclave; echo secret=$SECRET"},
		DotEnv:  []byte("SECRET=nitro-sealed\n"),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, string(result.Stdout), "hi from enclave")
	assert.Contains(t, string(result.Stdout), "secret=nitro-sealed", "the sealed .env reached the workload inside the enclave")
}
