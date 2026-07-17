package attest

import (
	"crypto/x509"
	"encoding/hex"
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
