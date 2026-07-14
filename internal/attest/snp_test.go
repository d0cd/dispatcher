package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- synthetic AMD-style cert chain (ARK -> ASK -> VCEK) -------------------

type snpChain struct {
	ark, ask, vcek *x509.Certificate
	arkKey         *ecdsa.PrivateKey
	vcekKey        *ecdsa.PrivateKey
}

func newSNPChain(t *testing.T) snpChain {
	t.Helper()
	mkCA := func(parent *x509.Certificate, parentKey *ecdsa.PrivateKey, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: cn},
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			// Mirror real AMD certs, which carry a KDS CRL distribution point so the
			// revocation check can locate the ARK-signed CRL.
			CRLDistributionPoints: []string{"https://kdsintf.amd.com/vcek/v1/Milan/crl"},
		}
		signer, signerKey := tmpl, key
		if parent != nil {
			signer, signerKey = parent, parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert, key
	}
	ark, arkKey := mkCA(nil, nil, "ARK")
	ask, askKey := mkCA(ark, arkKey, "ASK")

	// VCEK is a leaf signed by ASK.
	vcekKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "VCEK"}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ask, &vcekKey.PublicKey, askKey)
	require.NoError(t, err)
	vcek, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return snpChain{ark: ark, ask: ask, vcek: vcek, arkKey: arkKey, vcekKey: vcekKey}
}

// bigIntToLE renders n as a little-endian byte slice of the given width, the
// layout AMD uses for the report's r/s signature components.
func bigIntToLE(n *big.Int, width int) []byte {
	be := n.Bytes()
	out := make([]byte, width)
	for i := 0; i < len(be); i++ {
		out[i] = be[len(be)-1-i]
	}
	return out
}

// buildSNPReport assembles a 0x4A0-byte report and signs its 0x2A0-byte prefix
// with the VCEK key, matching the AMD SEV-SNP ABI fields the parser reads.
func buildSNPReport(t *testing.T, measurement, reportData []byte, reportedTCB, policy uint64, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	require.Len(t, measurement, 48)
	require.Len(t, reportData, 64)
	buf := make([]byte, 0x4A0)
	binary.LittleEndian.PutUint32(buf[0x00:], 2)      // version
	binary.LittleEndian.PutUint64(buf[0x08:], policy) // policy
	binary.LittleEndian.PutUint32(buf[0x34:], 1)      // signature algo: ECDSA P-384 / SHA-384
	binary.LittleEndian.PutUint64(buf[0x180:], reportedTCB)
	copy(buf[0x50:], reportData)
	copy(buf[0x90:], measurement)

	digest := sha512.Sum384(buf[:0x2A0])
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	copy(buf[0x2A0:], bigIntToLE(r, 72))
	copy(buf[0x2A0+72:], bigIntToLE(s, 72))
	return buf
}

func make48(b byte) []byte { return bytesRepeat(b, 48) }
func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// --- parse + claims --------------------------------------------------------

func TestParseSNPReport_ExtractsClaims(t *testing.T) {
	ch := newSNPChain(t)
	meas := make48(0x11)
	rd := bytesRepeat(0x22, 64)
	const policyDebug = 1 << 19
	rep, err := parseSNPReport(buildSNPReport(t, meas, rd, 9, 0, ch.vcekKey))
	require.NoError(t, err)

	c := rep.claims()
	assert.Equal(t, "sev-snp", c.TEEType)
	assert.Equal(t, hex.EncodeToString(meas), c.Measurement)
	assert.Equal(t, rd, c.ReportData)
	assert.Equal(t, uint64(9), c.TCB)
	assert.False(t, c.DebugEnabled)
	assert.False(t, c.MigrationEnabled)

	repDbg, err := parseSNPReport(buildSNPReport(t, meas, rd, 9, policyDebug, ch.vcekKey))
	require.NoError(t, err)
	assert.True(t, repDbg.claims().DebugEnabled, "policy debug bit must surface")
}

func TestParseSNPReport_RejectsShort(t *testing.T) {
	_, err := parseSNPReport(make([]byte, 100))
	require.Error(t, err)
}

// --- signature -------------------------------------------------------------

func TestVerifySNPSignature(t *testing.T) {
	ch := newSNPChain(t)
	raw := buildSNPReport(t, make48(1), bytesRepeat(2, 64), 1, 0, ch.vcekKey)
	rep, err := parseSNPReport(raw)
	require.NoError(t, err)
	require.NoError(t, verifySNPSignature(rep, ch.vcek), "VCEK-signed report verifies")

	// Tamper with the measurement (inside the signed region) -> signature fails.
	raw[0x90] ^= 0xFF
	tampered, err := parseSNPReport(raw)
	require.NoError(t, err)
	assert.Error(t, verifySNPSignature(tampered, ch.vcek))

	// A different VCEK key cannot have signed it.
	other := newSNPChain(t)
	assert.Error(t, verifySNPSignature(rep, other.vcek))
}

func TestVerifySNPSignature_RejectsBadAlgoAndKeyType(t *testing.T) {
	ch := newSNPChain(t)
	raw := buildSNPReport(t, make48(1), bytesRepeat(2, 64), 1, 0, ch.vcekKey)

	// Unsupported signature algorithm (anything but ECDSA-P384/SHA-384).
	raw[0x34] = 9
	rep, err := parseSNPReport(raw)
	require.NoError(t, err)
	err = verifySNPSignature(rep, ch.vcek)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm")

	// A non-ECDSA VCEK is rejected before any signature math.
	raw[0x34] = 1
	rep, err = parseSNPReport(raw)
	require.NoError(t, err)
	assert.Error(t, verifySNPSignature(rep, rsaLeafCert(t)), "VCEK must be ECDSA P-384")
}

// rsaLeafCert builds a self-signed RSA certificate, used to prove the SNP
// verifier rejects a non-ECDSA VCEK.
func rsaLeafCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// --- cert chain ------------------------------------------------------------

func TestVerifySNPChain(t *testing.T) {
	ch := newSNPChain(t)
	roots := []*x509.Certificate{ch.ark}
	require.NoError(t, verifySNPChain(ch.vcek, ch.ask, roots))

	// A foreign ARK must not validate this ASK.
	other := []*x509.Certificate{newSNPChain(t).ark}
	assert.Error(t, verifySNPChain(ch.vcek, ch.ask, other), "ASK chains to no pinned ARK")
	assert.Error(t, verifySNPChain(ch.vcek, newSNPChain(t).ask, roots), "VCEK not signed by the presented ASK")
	assert.Error(t, verifySNPChain(nil, ch.ask, roots), "an incomplete chain fails closed")
	assert.Error(t, verifySNPChain(ch.vcek, ch.ask, nil), "no pinned roots fails closed")

	// Multiple pinned roots: the ASK is accepted if ANY pinned root signed it.
	assert.NoError(t, verifySNPChain(ch.vcek, ch.ask, []*x509.Certificate{newSNPChain(t).ark, ch.ark}))
}
