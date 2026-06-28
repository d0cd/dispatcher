package cloudvm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

// --- synthetic AMD-style cert chain (ARK -> ASK -> VCEK) -------------------

type snpChain struct {
	ark, ask, vcek *x509.Certificate
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
			KeyUsage:              x509.KeyUsageCertSign,
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

	return snpChain{ark: ark, ask: ask, vcek: vcek, vcekKey: vcekKey}
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

// --- end-to-end attester ---------------------------------------------------

func TestSNPAttester_VerifyAccepts(t *testing.T) {
	ch := newSNPChain(t)
	meas := make48(0xAB)
	channelKey := []byte("in-tee-channel-public-key")

	att := &snpAttester{roots: []*x509.Certificate{ch.ark}, isReady: true,
		fetch: func(_ context.Context, _ *VMInfo, _, _ string, nonce []byte) (snpEvidence, error) {
			// The guest binds this run: REPORT_DATA = SHA-512(nonce || channelKey).
			rd := bindingHash(nonce, channelKey)
			return snpEvidence{
				report:     buildSNPReport(t, meas, rd, 5, 0, ch.vcekKey),
				vcek:       ch.vcek,
				ask:        ch.ask,
				channelKey: channelKey,
			}, nil
		}}

	req := types.ConfidentialRequirement{
		Required: true, Type: "sev-snp",
		Measurements: []string{hex.EncodeToString(meas)}, MinTCB: 5,
	}
	res, err := att.Verify(context.Background(), &VMInfo{ID: "vm"}, "/k", "u", req)
	require.NoError(t, err)
	assert.True(t, res.Verified)
	assert.Equal(t, "sev-snp", res.Type)
	assert.Equal(t, hex.EncodeToString(meas), res.Measurement)
	assert.Equal(t, uint64(5), res.TCB)
	assert.NotEmpty(t, res.Nonce, "the per-run nonce is recorded for the audit trail")
}

func TestSNPAttester_VerifyRejectsWrongMeasurement(t *testing.T) {
	ch := newSNPChain(t)
	channelKey := []byte("k")
	att := &snpAttester{roots: []*x509.Certificate{ch.ark}, isReady: true,
		fetch: func(_ context.Context, _ *VMInfo, _, _ string, nonce []byte) (snpEvidence, error) {
			return snpEvidence{
				report: buildSNPReport(t, make48(0x01), bindingHash(nonce, channelKey), 5, 0, ch.vcekKey),
				vcek:   ch.vcek, ask: ch.ask, channelKey: channelKey,
			}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev-snp",
		Measurements: []string{hex.EncodeToString(make48(0x99))}, MinTCB: 5}
	res, err := att.Verify(context.Background(), &VMInfo{}, "/k", "u", req)
	require.NoError(t, err, "a policy mismatch is a verdict, not an error")
	assert.False(t, res.Verified)
	assert.Contains(t, res.Verdict, "measurement")
}

func TestSNPAttester_VerifyRejectsReplay(t *testing.T) {
	ch := newSNPChain(t)
	meas := make48(0x07)
	// The guest binds a STALE nonce (not the one Verify generated) -> binding fails.
	stale := bytesRepeat(0xEE, 32)
	channelKey := []byte("k")
	att := &snpAttester{roots: []*x509.Certificate{ch.ark}, isReady: true,
		fetch: func(_ context.Context, _ *VMInfo, _, _ string, _ []byte) (snpEvidence, error) {
			return snpEvidence{
				report: buildSNPReport(t, meas, bindingHash(stale, channelKey), 5, 0, ch.vcekKey),
				vcek:   ch.vcek, ask: ch.ask, channelKey: channelKey,
			}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev-snp",
		Measurements: []string{hex.EncodeToString(meas)}, MinTCB: 5}
	res, err := att.Verify(context.Background(), &VMInfo{}, "/k", "u", req)
	require.NoError(t, err)
	assert.False(t, res.Verified)
	assert.Contains(t, res.Verdict, "REPORT_DATA")
}

func TestSNPAttester_RejectsTDXRequest(t *testing.T) {
	att := &snpAttester{isReady: true}
	_, err := att.Verify(context.Background(), &VMInfo{}, "/k", "u",
		types.ConfidentialRequirement{Required: true, Type: "tdx"})
	require.Error(t, err, "an AMD SEV-SNP attester cannot verify an Intel TDX report")
	assert.Contains(t, err.Error(), "tdx")
}

func TestSNPAttester_PropagatesFetchFailure(t *testing.T) {
	att := &snpAttester{roots: []*x509.Certificate{newSNPChain(t).ark}, isReady: true,
		fetch: func(_ context.Context, _ *VMInfo, _, _ string, _ []byte) (snpEvidence, error) {
			return snpEvidence{}, fmt.Errorf("guest unreachable")
		}}
	_, err := att.Verify(context.Background(), &VMInfo{}, "/k", "u",
		types.ConfidentialRequirement{Required: true, Type: "sev-snp"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "guest unreachable")
}

func TestSNPAttester_NoFetchWired(t *testing.T) {
	_, err := (&snpAttester{isReady: true}).Verify(context.Background(), &VMInfo{}, "/k", "u",
		types.ConfidentialRequirement{Required: true, Type: "sev-snp"})
	require.Error(t, err, "an attester with no fetch must error, not panic")
}

func TestSNPAttester_NotReadyByDefault(t *testing.T) {
	assert.False(t, (&snpAttester{}).ready(), "an attester with no live fetch must report not-ready")
	assert.True(t, (&snpAttester{isReady: true}).ready())
}
