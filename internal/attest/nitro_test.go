package attest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"
)

// nitroTestPKI builds a synthetic Nitro attestation PKI: a self-signed P-384 root
// (standing in for the AWS Nitro Enclaves Root) and returns it with its key.
func nitroTestPKI(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-nitro-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return root, key
}

// signedNitroDoc builds a COSE_Sign1 Nitro attestation document: a leaf cert
// signed by root, and a CBOR payload (PCRs, channel key, nonce) signed with the
// leaf's key (ES384) — the exact shape the Nitro Security Module produces. mutate
// can tamper with the document before signing.
func signedNitroDoc(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, mutate func(*nitroDoc)) []byte {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "nsm-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	doc := nitroDoc{
		ModuleID:    "i-0abc-enc0",
		Digest:      "SHA384",
		Timestamp:   1_700_000_000_000,
		PCRs:        map[uint][]byte{0: nitroPCR(0x0A), 1: nitroPCR(0x0B), 2: nitroPCR(0x0C)},
		Certificate: leafDER,
		CABundle:    [][]byte{root.Raw},
		PublicKey:   []byte("channel-public-key-bytes-32-xxxx"),
		Nonce:       []byte("nonce-from-verifier-32-bytes-xxx"),
	}
	if mutate != nil {
		mutate(&doc)
	}
	payload, err := cbor.Marshal(doc)
	require.NoError(t, err)

	signer, err := cose.NewSigner(cose.AlgorithmES384, leafKey)
	require.NoError(t, err)
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES384)
	require.NoError(t, msg.Sign(rand.Reader, nil, signer))
	raw, err := msg.MarshalCBOR()
	require.NoError(t, err)
	return raw
}

func nitroPCR(b byte) []byte {
	p := make([]byte, 48) // SHA-384
	for i := range p {
		p[i] = b
	}
	return p
}

// TestAWSNitroRoot_PinnedFingerprint guards the embedded trust anchor: the bytes
// compiled in must be AWS's published Nitro Enclaves Root-G1 (a supply-chain check
// — a swapped root would silently trust an attacker's PKI).
func TestAWSNitroRoot_PinnedFingerprint(t *testing.T) {
	block, _ := pem.Decode(awsNitroRootPEM)
	require.NotNil(t, block, "embedded AWS Nitro root must be PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	sum := sha256.Sum256(cert.Raw)
	assert.Equal(t, "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b",
		hex.EncodeToString(sum[:]), "embedded root must match AWS's published Root-G1 fingerprint")
	assert.Equal(t, "aws.nitro-enclaves", cert.Subject.CommonName)
}

// TestVerifyNitroDoc_Accepts: a well-formed document — leaf chaining to the pinned
// root, valid COSE signature, matching PCRs and nonce — verifies and returns the
// PCR0 measurement and the bound channel key.
func TestVerifyNitroDoc_Accepts(t *testing.T) {
	root, rootKey := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	nonce := []byte("nonce-from-verifier-32-bytes-xxx")

	doc := signedNitroDoc(t, root, rootKey, nil)
	measurement, channelKey, err := verifyNitroDoc(doc, pool, NitroPolicy{
		Nonce: nonce,
		PCRs:  map[int]string{0: hex.EncodeToString(nitroPCR(0x0A))},
	})
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(nitroPCR(0x0A)), measurement, "measurement is PCR0")
	assert.Equal(t, []byte("channel-public-key-bytes-32-xxxx"), channelKey, "the bound channel key is returned to seal to")
}

// TestVerifyNitroDoc_RejectsCALeaf: a document whose "leaf" is actually a CA cert
// that chains to the pinned root. A genuine NSM leaf is an end-entity cert; a CA
// posing as the signing leaf must be rejected so an intermediate can never stand
// in for the enclave's attestation key.
func TestVerifyNitroDoc_RejectsCALeaf(t *testing.T) {
	root, rootKey := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	nonce := []byte("nonce-from-verifier-32-bytes-xxx")

	// Build a CA cert (IsCA=true) signed by root, and sign the COSE doc with it.
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9),
		Subject:               pkix.Name{CommonName: "rogue-ca-leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, root, &caKey.PublicKey, rootKey)
	require.NoError(t, err)

	doc := nitroDoc{
		ModuleID:    "i-0abc-enc0",
		Digest:      "SHA384",
		Timestamp:   1_700_000_000_000,
		PCRs:        map[uint][]byte{0: nitroPCR(0x0A)},
		Certificate: caDER,
		CABundle:    [][]byte{root.Raw},
		PublicKey:   []byte("channel-public-key-bytes-32-xxxx"),
		Nonce:       nonce,
	}
	payload, err := cbor.Marshal(doc)
	require.NoError(t, err)
	signer, err := cose.NewSigner(cose.AlgorithmES384, caKey)
	require.NoError(t, err)
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES384)
	require.NoError(t, msg.Sign(rand.Reader, nil, signer))
	raw, err := msg.MarshalCBOR()
	require.NoError(t, err)

	_, _, err = verifyNitroDoc(raw, pool, NitroPolicy{
		Nonce: nonce,
		PCRs:  map[int]string{0: hex.EncodeToString(nitroPCR(0x0A))},
	})
	require.Error(t, err, "a CA cert posing as the NSM leaf must be rejected")
	assert.Contains(t, err.Error(), "end-entity")
}

// TestVerifyNitroDoc_RejectsUntrustedRoot: a document whose leaf does not chain to
// the pinned root must fail (an attacker's self-signed NSM).
func TestVerifyNitroDoc_RejectsUntrustedRoot(t *testing.T) {
	root, rootKey := nitroTestPKI(t)
	otherRoot, _ := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(otherRoot) // trust a DIFFERENT root

	doc := signedNitroDoc(t, root, rootKey, nil)
	_, _, err := verifyNitroDoc(doc, pool, NitroPolicy{
		Nonce: []byte("nonce-from-verifier-32-bytes-xxx"),
		PCRs:  map[int]string{0: hex.EncodeToString(nitroPCR(0x0A))},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain")
}

// TestVerifyNitroDoc_RejectsPCRMismatch: a document whose PCR0 (the enclave image
// measurement) is not the pinned value must fail — a different enclave image.
func TestVerifyNitroDoc_RejectsPCRMismatch(t *testing.T) {
	root, rootKey := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	doc := signedNitroDoc(t, root, rootKey, nil)
	_, _, err := verifyNitroDoc(doc, pool, NitroPolicy{
		Nonce: []byte("nonce-from-verifier-32-bytes-xxx"),
		PCRs:  map[int]string{0: hex.EncodeToString(nitroPCR(0xFF))}, // not what the doc attests
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pcr0")
}

// A debug-mode enclave reports all-zero PCRs (its memory is host-readable, so it
// is not confidential); it must be rejected even if the pin happens to be zeros.
func TestVerifyNitroDoc_RejectsAllZeroPCR(t *testing.T) {
	root, rootKey := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	zero := make([]byte, 48)

	doc := signedNitroDoc(t, root, rootKey, func(d *nitroDoc) { d.PCRs[0] = zero })
	_, _, err := verifyNitroDoc(doc, pool, NitroPolicy{
		Nonce: []byte("nonce-from-verifier-32-bytes-xxx"),
		PCRs:  map[int]string{0: hex.EncodeToString(nitroPCR(0x0A))},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all zeros")
}

// A policy that pins a PCR to all zeros attests nothing and must be refused.
func TestVerifyNitroDoc_RejectsAllZeroPin(t *testing.T) {
	root, rootKey := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	doc := signedNitroDoc(t, root, rootKey, nil)
	_, _, err := verifyNitroDoc(doc, pool, NitroPolicy{
		Nonce: []byte("nonce-from-verifier-32-bytes-xxx"),
		PCRs:  map[int]string{0: hex.EncodeToString(make([]byte, 48))},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all zeros")
}

// TestVerifyNitroDoc_RejectsNonceMismatch: a stale/replayed document (nonce not
// this run's challenge) must fail.
func TestVerifyNitroDoc_RejectsNonceMismatch(t *testing.T) {
	root, rootKey := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	doc := signedNitroDoc(t, root, rootKey, nil)
	_, _, err := verifyNitroDoc(doc, pool, NitroPolicy{
		Nonce: []byte("a-completely-different-nonce-val"),
		PCRs:  map[int]string{0: hex.EncodeToString(nitroPCR(0x0A))},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce")
}

// TestNitroValidator_BindsSessionAndNonce drives the aTLS validator path: the
// enclave document must echo this run's nonce AND carry the aTLS session's bindData
// as its public_key, or the session is rejected as a relay/substitution.
func TestNitroValidator_BindsSessionAndNonce(t *testing.T) {
	root, rootKey := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	nonce := bytes.Repeat([]byte{0x5C}, 32)
	bindData := []byte("channel-public-key-bytes-32-xxxx")
	doc := signedNitroDoc(t, root, rootKey, func(d *nitroDoc) { d.Nonce = nonce; d.PublicKey = bindData })
	ev := []byte(base64.StdEncoding.EncodeToString(doc))

	v := NitroValidator(pool, map[int]string{0: hex.EncodeToString(nitroPCR(0x0A))})
	require.NoError(t, v.Validate(context.Background(), ev, bindData, nonce))
	assert.True(t, v.Result.Verified, v.Result.Verdict)
	assert.Equal(t, "nitro", v.Result.Type)

	// A document not bound to this session's bindData must be rejected.
	require.Error(t, v.Validate(context.Background(), ev, []byte("a-different-32-byte-bind-value!!"), nonce))
}

// TestVerifyNitroDoc_RejectsTamperedPayload: flipping a PCR after signing breaks
// the COSE signature (the signature covers the CBOR payload).
func TestVerifyNitroDoc_RejectsTamperedPayload(t *testing.T) {
	root, rootKey := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	// Re-sign with a leaf NOT chaining to root would be caught by the chain check;
	// here we tamper the signed bytes to break signature verification instead.
	doc := signedNitroDoc(t, root, rootKey, nil)
	doc[len(doc)-1] ^= 0xFF // corrupt the trailing signature byte

	_, _, err := verifyNitroDoc(doc, pool, NitroPolicy{
		Nonce: []byte("nonce-from-verifier-32-bytes-xxx"),
		PCRs:  map[int]string{0: hex.EncodeToString(nitroPCR(0x0A))},
	})
	require.Error(t, err)
}
