package cloudvm

import (
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGolden_AWSSNPReport verifies dispatcher's AWS SEV-SNP verifier against a
// REAL VLEK-signed report captured from a live SEV-SNP EC2 instance (m6a.large,
// Milan). It confirms go-sev-guest verifies the firmware signature + the VLEK→
// ASVK→ARK chain (the ASVK/ARK supplied from the captured KDS chain), and that we
// extract the measurement + REPORT_DATA correctly. Fixtures are git-ignored, so
// the test skips without them.
func TestGolden_AWSSNPReport(t *testing.T) {
	dir := filepath.Join(fixturesDir(), "aws-snp")
	b64 := strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "report.b64"))))
	chain := skipUnlessFixture(t, filepath.Join(dir, "vlek_chain.pem"))
	wantRD, err := hex.DecodeString(strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "report-data.hex")))))
	require.NoError(t, err)

	crlDER := skipUnlessFixture(t, filepath.Join(dir, "vlek_crl.der"))
	raw, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)

	// Serve the captured CRL offline so ARK-pin + revocation run without KDS.
	prev := awsCRLGetter
	awsCRLGetter = func(string) ([]byte, error) { return crlDER, nil }
	t.Cleanup(func() { awsCRLGetter = prev })

	claims, err := verifyAWSSNPReport(raw, func(string) ([]byte, error) { return chain, nil })
	require.NoError(t, err, "a real VLEK-signed report must verify via go-sev-guest + the pinned ARK + CRL")

	assert.Equal(t, "sev-snp", claims.TEEType)
	assert.Len(t, claims.Measurement, 2*snpLenMeas, "48-byte measurement as hex")
	// The REPORT_DATA we set on capture must round-trip (confirms the binding channel).
	require.Len(t, wantRD, 64)
	assert.Equal(t, wantRD, claims.ReportData, "REPORT_DATA must round-trip — the binding field")
	t.Logf("verified real AWS SEV-SNP report: measurement=%s debug=%v tcb=%#x", claims.Measurement, claims.DebugEnabled, claims.TCB)
}
