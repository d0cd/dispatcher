package attest

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// capturePCR11 is a capture-only atls.Validator: it reads PCR11 out of the
// azure-snp evidence bundle without pinning, so a first run can learn the PCR11
// to pin. It proves nothing about image identity — the pinned re-run below does.
type capturePCR11 struct{ pcr11, measurement string }

func (c *capturePCR11) Validate(_ context.Context, evidence, _, _ []byte) error {
	ev, err := parseAzureSNPEvidence(evidence)
	if err != nil {
		return err
	}
	c.pcr11 = hex.EncodeToString(ev.PCRs[11])
	if rep, err := parseSNPReport(ev.SNPReport); err == nil {
		c.measurement = hex.EncodeToString(rep.measurement)
	}
	return nil
}

// TestGolden_AzureSNPLiveExchange drives the full direct SNP+vTPM path over aTLS
// against a live Azure confidential VM running dispatcher-attest-azuresnp: attest
// (genuine SEV-SNP → runtime-data/AK binding → AK-signed PCR11 quote → pinned
// PCR11, all committed to the aTLS session's bindData) and deliver+run the sealed
// workload over the same attested TLS session — exactly the azure-snp adapter's
// path (AzureSNPValidatorPinned + RunOverATLS), minus provisioning. Gated on the
// live endpoint. With no pinned PCR11 it captures whatever the running image
// reports, then re-attests against that pin in a fresh session.
//
//	DISPATCHER_AZURESNP_LIVE_ENDPOINT=<vm-ip>:8443 \
//	[DISPATCHER_AZURESNP_LIVE_PCR11=<pcr11 hex>] \
//	go test ./internal/attest -run TestGolden_AzureSNPLiveExchange -v
func TestGolden_AzureSNPLiveExchange(t *testing.T) {
	endpoint := os.Getenv("DISPATCHER_AZURESNP_LIVE_ENDPOINT")
	if endpoint == "" {
		t.Skip("set DISPATCHER_AZURESNP_LIVE_ENDPOINT to run against a live CVM")
	}
	addr := strings.TrimPrefix(endpoint, "http://")
	ctx := context.Background()

	pcr11 := strings.TrimSpace(os.Getenv("DISPATCHER_AZURESNP_LIVE_PCR11"))
	measurement := strings.TrimSpace(os.Getenv("DISPATCHER_AZURESNP_LIVE_MEASUREMENT"))
	if pcr11 == "" {
		capture := &capturePCR11{}
		_, err := agent.RunOverATLS(ctx, addr, capture, agent.Payload{Command: []string{"true"}})
		require.NoError(t, err, "capture run")
		require.NotEmpty(t, capture.pcr11, "the evidence bundle must carry PCR11")
		pcr11 = capture.pcr11
		measurement = capture.measurement
		t.Logf("captured PCR11 = %s, launch measurement = %s", pcr11, measurement)
	}

	v := AzureSNPValidatorPinned(map[int]string{11: pcr11}, measurement, 0)
	result, err := agent.RunOverATLS(ctx, addr, v, agent.Payload{
		Command: []string{"sh", "-c", "echo hi from CVM; echo secret=$SECRET"},
		DotEnv:  []byte("SECRET=azuresnp-sealed\n"),
	})
	require.NoError(t, err)
	require.True(t, v.Result.Verified, v.Result.Verdict)
	assert.Equal(t, "sev-snp", v.Result.Type)
	assert.Equal(t, pcr11, v.Result.Measurement, "the attested measurement is the pinned PCR11")
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, string(result.Stdout), "hi from CVM")
	assert.Contains(t, string(result.Stdout), "secret=azuresnp-sealed", "the sealed .env reached the workload inside the CVM")
}
