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

// TestGolden_AzureSNPLiveExchange drives the full direct SNP+vTPM path against a
// live Azure confidential VM running dispatcher-attest-azuresnp: fetch the
// evidence bundle, verify it (genuine SEV-SNP → runtime-data/AK binding →
// AK-signed PCR11 quote → pinned PCR11), seal source/.env to the bound channel
// key, run inside the CVM, and open the sealed result. Gated on the live endpoint.
// This validates the whole pipeline on real Azure hardware without needing the
// measured UKI image — pin whatever PCR11 the running image reports.
//
//	DISPATCHER_AZURESNP_LIVE_ENDPOINT=http://<vm-ip>:8443 \
//	DISPATCHER_AZURESNP_LIVE_PCR11=<pcr11 hex the agent quotes> \
//	go test ./internal/attest -run TestGolden_AzureSNPLiveExchange -v
func TestGolden_AzureSNPLiveExchange(t *testing.T) {
	endpoint := os.Getenv("DISPATCHER_AZURESNP_LIVE_ENDPOINT")
	if endpoint == "" {
		t.Skip("set DISPATCHER_AZURESNP_LIVE_ENDPOINT (+ DISPATCHER_AZURESNP_LIVE_PCR11) to run against a live CVM")
	}
	pcr11 := strings.TrimSpace(os.Getenv("DISPATCHER_AZURESNP_LIVE_PCR11"))
	require.NotEmpty(t, pcr11, "DISPATCHER_AZURESNP_LIVE_PCR11 is required")

	ctx := context.Background()
	att := NewAzureSNPAttester(map[int]string{11: pcr11}, endpoint)
	res, err := att.Verify(ctx, types.ConfidentialRequirement{Required: true, Type: "sev-snp"})
	require.NoError(t, err)
	require.True(t, res.Verified, res.Verdict)
	require.NotEmpty(t, res.ChannelKey, "a verified result carries the bound channel key to seal to")
	assert.Equal(t, pcr11, res.Measurement, "the attested measurement is the pinned PCR11")

	result, err := agent.RunSealedExchange(ctx, endpoint, res.ChannelKey, agent.Payload{
		Command: []string{"sh", "-c", "echo hi from CVM; echo secret=$SECRET"},
		DotEnv:  []byte("SECRET=azuresnp-sealed\n"),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, string(result.Stdout), "hi from CVM")
	assert.Contains(t, string(result.Stdout), "secret=azuresnp-sealed", "the sealed .env reached the workload inside the CVM")
}
