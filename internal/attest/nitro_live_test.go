package attest

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// TestGolden_NitroLiveExchange drives the full AWS Nitro path over aTLS against a
// live enclave running dispatcher-attest-nitro, reached via dispatcher-nitro-proxy
// on the parent: attest (COSE document chained to the pinned Root-G1, nonce +
// pinned PCR0, committed to the aTLS session's bindData) and deliver+run the sealed
// workload over the same attested TLS session — exactly the Nitro adapter's path
// (NitroValidatorPinned + RunOverATLS), minus provisioning. Gated on the live
// endpoint so CI stays offline.
//
//	DISPATCHER_NITRO_LIVE_ENDPOINT=<parent-ip>:8443 \
//	DISPATCHER_NITRO_LIVE_PCR0=<pcr0 hex from build-eif.sh> \
//	go test ./internal/attest -run TestGolden_NitroLiveExchange -v
func TestGolden_NitroLiveExchange(t *testing.T) {
	endpoint := os.Getenv("DISPATCHER_NITRO_LIVE_ENDPOINT")
	if endpoint == "" {
		t.Skip("set DISPATCHER_NITRO_LIVE_ENDPOINT (+ DISPATCHER_NITRO_LIVE_PCR0) to run against a live enclave")
	}
	pcr0 := strings.TrimSpace(os.Getenv("DISPATCHER_NITRO_LIVE_PCR0"))
	require.NotEmpty(t, pcr0, "DISPATCHER_NITRO_LIVE_PCR0 is required")
	addr := strings.TrimPrefix(endpoint, "http://")
	ctx := context.Background()

	v := NitroValidatorPinned(map[int]string{0: pcr0})
	result, err := agent.RunOverATLS(ctx, addr, v, agent.Payload{
		Command: []string{"sh", "-c", "echo hi from enclave; echo secret=$SECRET"},
		DotEnv:  []byte("SECRET=nitro-sealed\n"),
	})
	require.NoError(t, err)
	require.True(t, v.Result.Verified, v.Result.Verdict)
	assert.Equal(t, "nitro", v.Result.Type)
	assert.Equal(t, pcr0, v.Result.Measurement, "the attested measurement is the pinned enclave PCR0")
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, string(result.Stdout), "hi from enclave")
	assert.Contains(t, string(result.Stdout), "secret=nitro-sealed", "the sealed .env reached the workload inside the enclave")
}
