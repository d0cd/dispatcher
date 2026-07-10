package cloudvm

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These golden tests run the verifier cores against REAL attestation evidence
// captured from a live confidential VM (see experiments/confidential-attestation).
// They close the "format bind" gap: confirming the AMD SEV-SNP byte layout and
// the MAA claim names we coded against match what the hardware/service actually
// emit. With no fixtures present they skip, so CI stays fully offline.
//
// Capture fixtures into experiments/confidential-attestation/fixtures (or point
// DISPATCHER_ATTESTATION_FIXTURES elsewhere), then `go test ./internal/cloudvm`.

func fixturesDir() string {
	if d := os.Getenv("DISPATCHER_ATTESTATION_FIXTURES"); d != "" {
		return d
	}
	return filepath.Join("..", "..", "experiments", "confidential-attestation", "fixtures")
}

// skipUnlessFixture skips the test unless the named file exists, returning its
// contents otherwise.
func skipUnlessFixture(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no fixture at %s — capture one with experiments/confidential-attestation (%v)", path, err)
	}
	return b
}

func loadPEMCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(skipUnlessFixture(t, path))
	require.NotNil(t, block, "no PEM block in %s", path)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func TestGolden_SNPReport(t *testing.T) {
	dir := filepath.Join(fixturesDir(), "snp")
	raw := skipUnlessFixture(t, filepath.Join(dir, "report.bin"))

	report, err := parseSNPReport(raw)
	require.NoError(t, err, "real report must parse against the ABI offsets we coded")

	vcek := loadPEMCert(t, filepath.Join(dir, "vcek.pem"))
	ask := loadPEMCert(t, filepath.Join(dir, "ask.pem"))
	ark := loadPEMCert(t, filepath.Join(dir, "ark.pem"))

	require.NoError(t, verifySNPChain(vcek, ask, []*x509.Certificate{ark}), "real VCEK<-ASK<-ARK must chain")
	require.NoError(t, verifySNPSignature(report, vcek), "real firmware signature must verify (confirms signed-region length + r/s layout)")

	claims := report.claims()
	// The captured report-data round-trips, confirming the REPORT_DATA offset.
	wantRD, err := hex.DecodeString(strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "report-data.hex")))))
	require.NoError(t, err)
	assert.Equal(t, wantRD, claims.ReportData, "REPORT_DATA offset mismatch — the ABI layout is wrong")
	assert.Len(t, claims.Measurement, 2*snpLenMeas, "measurement must be a 48-byte hex string")
	t.Logf("verified real SEV-SNP report: measurement=%s tcb=%d debug=%v", claims.Measurement, claims.TCB, claims.DebugEnabled)
}

// jwksKeys parses a JWKS document (MAA publishes signing certs in x5c) into the
// kid->public-key map verifyMAAToken expects.
func jwksKeys(t *testing.T, raw []byte) map[string]crypto.PublicKey {
	t.Helper()
	var doc struct {
		Keys []struct {
			Kid string   `json:"kid"`
			X5c []string `json:"x5c"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	keys := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		require.NotEmpty(t, k.X5c, "MAA JWKS entry %q has no x5c chain", k.Kid)
		der, err := base64.StdEncoding.DecodeString(k.X5c[0])
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		keys[k.Kid] = cert.PublicKey
	}
	return keys
}

func TestGolden_MAAToken(t *testing.T) {
	dir := filepath.Join(fixturesDir(), "maa")
	token := strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "token.jwt"))))
	keys := jwksKeys(t, skipUnlessFixture(t, filepath.Join(dir, "jwks.json")))

	claims, err := verifyMAAToken(token, keys, "")
	require.NoError(t, err, "real MAA token must verify (confirms signature + the compliance/type claim names)")

	assert.Contains(t, []string{"sev-snp", "tdx"}, claims.TEEType)
	assert.NotEmpty(t, claims.Measurement, "launchmeasurement claim name mismatch — got empty measurement")
	assert.NotEmpty(t, claims.ReportData, "reportdata claim name mismatch — got empty report data")
	t.Logf("verified real MAA token: tee=%s measurement=%s", claims.TEEType, claims.Measurement)
}
