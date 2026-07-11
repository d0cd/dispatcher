package attest

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadCRTCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "no PEM block in %s", path)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func TestAMDRoots_PinnedAndSelfSigned(t *testing.T) {
	require.Len(t, amdRoots, 3, "Milan, Genoa, Turin ARK roots are pinned")
	cns := map[string]bool{}
	for _, r := range amdRoots {
		assert.True(t, r.IsCA, "ARK %s must be a CA", r.Subject.CommonName)
		require.NoError(t, r.CheckSignatureFrom(r), "ARK %s must be self-signed", r.Subject.CommonName)
		cns[r.Subject.CommonName] = true
	}
	for _, want := range []string{"ARK-Milan", "ARK-Genoa", "ARK-Turin"} {
		assert.True(t, cns[want], "missing pinned root %s", want)
	}
}

// TestAMDRoots_ValidateRealASK is the offline payoff of pinning: the real ASK
// intermediates captured from AMD KDS must each chain to a pinned ARK.
func TestAMDRoots_ValidateRealASK(t *testing.T) {
	for _, model := range []string{"milan", "genoa", "turin"} {
		ask := loadCRTCert(t, filepath.Join("testdata", "amd_ask", "ask-"+model+".crt"))
		chained := false
		for _, ark := range amdRoots {
			if ask.CheckSignatureFrom(ark) == nil {
				chained = true
				break
			}
		}
		assert.True(t, chained, "real %s ASK must chain to a pinned ARK", model)
	}
}
