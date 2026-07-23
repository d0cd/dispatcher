package attest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	legacytpm "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// runtimeDataWithAK builds the HCL runtime-data JSON that carries the vTPM
// Attestation Key as the "HCLAkPub" JWK — the exact shape Azure emits.
func runtimeDataWithAK(t *testing.T, ak *rsa.PublicKey) []byte {
	t.Helper()
	eb := make([]byte, 4)
	eb[0] = byte(ak.E >> 24)
	eb[1] = byte(ak.E >> 16)
	eb[2] = byte(ak.E >> 8)
	eb[3] = byte(ak.E)
	// trim leading zero bytes of the exponent
	i := 0
	for i < len(eb)-1 && eb[i] == 0 {
		i++
	}
	doc := map[string]any{
		"keys": []map[string]any{{
			"kid": "HCLAkPub", "kty": "RSA", "key_ops": []string{"sign"},
			"e": base64.RawURLEncoding.EncodeToString(eb[i:]),
			"n": base64.RawURLEncoding.EncodeToString(ak.N.Bytes()),
		}},
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)
	return b
}

// signedQuote builds a TPM quote (TPMS_ATTEST) over the given PCRs with extraData
// (the run+channel binding) and signs it with the AK — what the vTPM produces.
func signedQuote(t *testing.T, akPriv *rsa.PrivateKey, pcrs map[uint32][]byte, extraData []byte) (quote, sig []byte) {
	t.Helper()
	// The quote commits to SHA-256(concatenated selected PCR values), PCRs ordered
	// ascending — the digest the TPM computes over the selection.
	h := sha256.New()
	h.Write(pcrs[11])
	digest := h.Sum(nil)

	ad := legacytpm.AttestationData{
		Magic:           0xff544347,
		Type:            legacytpm.TagAttestQuote,
		QualifiedSigner: legacytpm.Name{},
		ExtraData:       tpmutil.U16Bytes(extraData),
		AttestedQuoteInfo: &legacytpm.QuoteInfo{
			PCRSelection: legacytpm.PCRSelection{Hash: legacytpm.AlgSHA256, PCRs: []int{11}},
			PCRDigest:    tpmutil.U16Bytes(digest),
		},
	}
	quote, err := ad.Encode()
	require.NoError(t, err)

	signed := sha256.Sum256(quote)
	sig, err = rsa.SignPKCS1v15(rand.Reader, akPriv, crypto.SHA256, signed[:])
	require.NoError(t, err)
	return quote, sig
}

// arkSignedCRL builds an ARK-signed CRL revoking the given serials (nil = none),
// the shape azureSNPCheckRevocation fetches from AMD KDS in production.
func arkSignedCRL(t *testing.T, ch snpChain, revoked ...*big.Int) []byte {
	t.Helper()
	return arkSignedCRLUntil(t, ch, time.Now().Add(time.Hour), revoked...)
}

// arkSignedCRLUntil is arkSignedCRL with a chosen NextUpdate (for freshness tests).
func arkSignedCRLUntil(t *testing.T, ch snpChain, nextUpdate time.Time, revoked ...*big.Int) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Now().Add(-time.Hour)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                nextUpdate.Add(-2 * time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, ch.ark, ch.arkKey)
	require.NoError(t, err)
	return der
}

// installCRL points the revocation seam at a fixed CRL for the test's duration.
func installCRL(t *testing.T, crl []byte) {
	t.Helper()
	prev := azureSNPCRLGetter
	azureSNPCRLGetter = func(string) ([]byte, error) { return crl, nil }
	t.Cleanup(func() { azureSNPCRLGetter = prev })
}

// azureEvidence assembles a full, valid Azure SNP+vTPM evidence bundle bound to
// nonce+channelKey, returning it plus the AMD roots to trust. mutate can tamper.
func azureEvidence(t *testing.T, nonce, channelKey []byte, pcr11 []byte, mutate func(*agent.AzureSNPEvidence)) (agent.AzureSNPEvidence, []*x509.Certificate) {
	t.Helper()
	ch := newSNPChain(t)
	installCRL(t, arkSignedCRL(t, ch)) // default: an empty (nothing-revoked) CRL
	akPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	runtimeData := runtimeDataWithAK(t, &akPriv.PublicKey)
	// Azure binds the runtime data into the SNP report's REPORT_DATA as its SHA-256
	// in the first 32 bytes (the rest zero).
	var reportData [64]byte
	rdHash := sha256.Sum256(runtimeData)
	copy(reportData[:], rdHash[:])

	report := buildSNPReport(t, make48(0x11), reportData[:], 9, 0, ch.vcekKey)

	pcrs := map[uint32][]byte{11: pcr11}
	quote, sig := signedQuote(t, akPriv, pcrs, agent.MAABindingNonce(nonce, channelKey))

	ev := agent.AzureSNPEvidence{
		SNPReport:   report,
		VCEK:        ch.vcek.Raw,
		ASK:         ch.ask.Raw,
		RuntimeData: runtimeData,
		Quote:       quote,
		QuoteSig:    sig,
		PCRs:        pcrs,
		ChannelKey:  channelKey,
	}
	if mutate != nil {
		mutate(&ev)
	}
	return ev, []*x509.Certificate{ch.ark}
}

// azureEvidencePolicy builds a valid bundle with a chosen SNP guest policy and
// reported TCB, for the policy/TCB rejection tests.
func azureEvidencePolicy(t *testing.T, nonce, channelKey, pcr11 []byte, policy, tcb uint64) (agent.AzureSNPEvidence, []*x509.Certificate) {
	t.Helper()
	ch := newSNPChain(t)
	installCRL(t, arkSignedCRL(t, ch)) // default: an empty (nothing-revoked) CRL
	akPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	runtimeData := runtimeDataWithAK(t, &akPriv.PublicKey)
	var reportData [64]byte
	rdHash := sha256.Sum256(runtimeData)
	copy(reportData[:], rdHash[:])
	report := buildSNPReport(t, make48(0x11), reportData[:], tcb, policy, ch.vcekKey)
	pcrs := map[uint32][]byte{11: pcr11}
	quote, sig := signedQuote(t, akPriv, pcrs, agent.MAABindingNonce(nonce, channelKey))
	return agent.AzureSNPEvidence{
		SNPReport: report, VCEK: ch.vcek.Raw, ASK: ch.ask.Raw, RuntimeData: runtimeData,
		Quote: quote, QuoteSig: sig, PCRs: pcrs, ChannelKey: channelKey,
	}, []*x509.Certificate{ch.ark}
}

// A genuine-hardware report with the DEBUG policy bit set must be rejected — a
// debug guest lets the host read/write guest memory and forge the vTPM AK, a full
// attestation bypass. Same for MIGRATE_MA and a TCB below the run's minimum.
func TestVerifyAzureSNP_RejectsDebugPolicy(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]
	ev, roots := azureEvidencePolicy(t, nonce, channelKey, pcr11, snpPolicyDebug, 9)
	_, _, err := verifyAzureSNP(ev, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)), Roots: roots, Nonce: nonce, PCRs: map[int]string{11: hex.EncodeToString(pcr11)}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "debug")
}

func TestVerifyAzureSNP_RejectsMigrateMA(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]
	ev, roots := azureEvidencePolicy(t, nonce, channelKey, pcr11, snpPolicyMigrateMA, 9)
	_, _, err := verifyAzureSNP(ev, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)), Roots: roots, Nonce: nonce, PCRs: map[int]string{11: hex.EncodeToString(pcr11)}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "migration")
}

func TestVerifyAzureSNP_RejectsBelowMinTCB(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]
	ev, roots := azureEvidencePolicy(t, nonce, channelKey, pcr11, 0, 5) // reported TCB 5
	_, _, err := verifyAzureSNP(ev, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)), Roots: roots, Nonce: nonce, PCRs: map[int]string{11: hex.EncodeToString(pcr11)}, MinTCB: 9})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TCB")
}

// TestVerifyAzureSNP_Accepts: a well-formed bundle — genuine SNP report binding the
// runtime data, the AK signing a quote over the pinned PCR11 with the run+channel
// binding — verifies and returns PCR11 as the measurement + the bound channel key.
func TestVerifyAzureSNP_Accepts(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32] // PCR values are the bank hash width (SHA-256 = 32)

	ev, roots := azureEvidence(t, nonce, channelKey, pcr11, nil)
	measurement, gotKey, err := verifyAzureSNP(ev, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)),
		Roots: roots, Nonce: nonce, PCRs: map[int]string{11: hex.EncodeToString(pcr11)},
	})
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(pcr11), measurement, "measurement is the pinned PCR11")
	assert.Equal(t, channelKey, gotKey, "the bound channel key is returned to seal to")
}

// The SNP launch MEASUREMENT roots the vTPM AK in trusted Azure firmware. Without
// it, an attacker with their own ARK-chaining SNP box could embed their own AK in
// REPORT_DATA and forge the entire vTPM/PCR chain. A missing or mismatched pin
// must fail closed.
func TestVerifyAzureSNP_EnforcesLaunchMeasurement(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]
	ev, roots := azureEvidence(t, nonce, channelKey, pcr11, nil)

	pol := func(meas string) AzureSNPPolicy {
		return AzureSNPPolicy{Roots: roots, Nonce: nonce, PCRs: map[int]string{11: hex.EncodeToString(pcr11)}, Measurement: meas}
	}

	// The genuine report's launch measurement (make48(0x11)) verifies.
	_, _, err := verifyAzureSNP(ev, pol(hex.EncodeToString(make48(0x11))))
	require.NoError(t, err)

	// No launch measurement pinned → fail closed (the AK can't be rooted).
	_, _, err = verifyAzureSNP(ev, pol(""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "launch measurement")

	// A mismatched launch measurement → reject (attacker firmware).
	_, _, err = verifyAzureSNP(ev, pol(hex.EncodeToString(make48(0x22))))
	require.Error(t, err)
}

// TestCaptureAzureSNPPCR11_DerivesVerifiedPCR11: capture-time verification of a
// genuine bundle returns the quoted PCR11 without a pre-existing pin — so the value
// pinned at capture is one the hardware actually attested, not one an endpoint
// merely claimed. A forged quote must be refused, closing the poisoned-pin gap.
func TestCaptureAzureSNPPCR11_DerivesVerifiedPCR11(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]

	ev, roots := azureEvidence(t, nonce, channelKey, pcr11, nil)
	got, _, err := captureAzureSNPPCR11(ev, roots, nonce)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(pcr11), got, "capture derives the hardware-attested PCR11")
}

func TestCaptureAzureSNPPCR11_RejectsForgedQuote(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]

	ev, roots := azureEvidence(t, nonce, channelKey, pcr11, func(e *agent.AzureSNPEvidence) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		signed := sha256.Sum256(e.Quote)
		e.QuoteSig, _ = rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, signed[:])
	})
	_, _, err := captureAzureSNPPCR11(ev, roots, nonce)
	require.Error(t, err, "a bundle not signed by the bound AK cannot be captured")
}

// TestVerifyAzureSNP_RejectsUnquotedPinnedPCR: a pinned PCR that the signed quote
// does not actually cover must fail — the value in the evidence map for it is
// unverified, so it can't be trusted even if it equals the pin.
func TestVerifyAzureSNP_RejectsUnquotedPinnedPCR(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]

	// Add PCR7 to the evidence map that the quote (which covers only PCR11) never
	// signed, then pin PCR7 — verification must reject it as unquoted.
	ev, roots := azureEvidence(t, nonce, channelKey, pcr11, func(e *agent.AzureSNPEvidence) {
		e.PCRs[7] = make48(0x77)[:32]
	})
	_, _, err := verifyAzureSNP(ev, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)),
		Roots: roots, Nonce: nonce, PCRs: map[int]string{7: hex.EncodeToString(make48(0x77)[:32])},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quote")
}

// TestVerifyAzureSNP_RejectsPCRMismatch: a different PCR11 (a different measured
// image / agent) must fail.
func TestVerifyAzureSNP_RejectsPCRMismatch(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]

	ev, roots := azureEvidence(t, nonce, channelKey, pcr11, nil)
	_, _, err := verifyAzureSNP(ev, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)),
		Roots: roots, Nonce: nonce, PCRs: map[int]string{11: hex.EncodeToString(make48(0xCD)[:32])},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pcr11")
}

// TestVerifyAzureSNP_RejectsUnboundAK: if the runtime data (and thus the AK) isn't
// the one bound in the SNP report's REPORT_DATA, the quote can't be trusted.
func TestVerifyAzureSNP_RejectsUnboundAK(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]

	ev, roots := azureEvidence(t, nonce, channelKey, pcr11, func(e *agent.AzureSNPEvidence) {
		e.RuntimeData = append([]byte(nil), e.RuntimeData...)
		e.RuntimeData[len(e.RuntimeData)-2] ^= 0xFF // tamper → SHA-256 no longer matches REPORT_DATA
	})
	_, _, err := verifyAzureSNP(ev, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)),
		Roots: roots, Nonce: nonce, PCRs: map[int]string{11: hex.EncodeToString(pcr11)},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "runtime data")
}

// TestVerifyAzureSNP_RejectsNonceMismatch: a quote whose extraData isn't this run's
// nonce+channel binding is a replay/relay and must fail.
func TestVerifyAzureSNP_RejectsNonceMismatch(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]

	ev, roots := azureEvidence(t, nonce, channelKey, pcr11, nil)
	_, _, err := verifyAzureSNP(ev, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)),
		Roots: roots, Nonce: bytesRepeat(0x11, 32), PCRs: map[int]string{11: hex.EncodeToString(pcr11)},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binding")
}

// TestVerifyAzureSNP_RejectsForgedQuote: a quote signed by a key other than the
// bound AK must fail signature verification.
func TestVerifyAzureSNP_RejectsForgedQuote(t *testing.T) {
	nonce := bytesRepeat(0x5a, 32)
	channelKey := []byte("azure-channel-public-key-32-byte")
	pcr11 := make48(0xAB)[:32]

	ev, roots := azureEvidence(t, nonce, channelKey, pcr11, func(e *agent.AzureSNPEvidence) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		signed := sha256.Sum256(e.Quote)
		e.QuoteSig, _ = rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, signed[:])
	})
	_, _, err := verifyAzureSNP(ev, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)),
		Roots: roots, Nonce: nonce, PCRs: map[int]string{11: hex.EncodeToString(pcr11)},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quote signature")
}

// The measured Azure SNP path must reject a platform whose VCEK/ASK AMD cert has
// been revoked, and must fail closed (never fail open) when the ARK-signed CRL is
// missing, unreachable, or not chained to a pinned root.
func TestAzureSNPCheckRevocation(t *testing.T) {
	ch := newSNPChain(t)

	t.Run("passes when nothing is revoked", func(t *testing.T) {
		installCRL(t, arkSignedCRL(t, ch))
		require.NoError(t, azureSNPCheckRevocation(ch.vcek, ch.ask, ch.ark))
	})

	t.Run("rejects a revoked VCEK", func(t *testing.T) {
		installCRL(t, arkSignedCRL(t, ch, ch.vcek.SerialNumber))
		err := azureSNPCheckRevocation(ch.vcek, ch.ask, ch.ark)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "VCEK has been revoked")
	})

	t.Run("rejects a revoked ASK", func(t *testing.T) {
		installCRL(t, arkSignedCRL(t, ch, ch.ask.SerialNumber))
		err := azureSNPCheckRevocation(ch.vcek, ch.ask, ch.ark)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ASK has been revoked")
	})

	t.Run("rejects a CRL signed by a different ARK than the ASK.s issuer (cross-family)", func(t *testing.T) {
		installCRL(t, arkSignedCRL(t, newSNPChain(t))) // signed by a foreign ARK
		err := azureSNPCheckRevocation(ch.vcek, ch.ask, ch.ark)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuing ARK")
	})

	t.Run("fails closed when the CRL can't be fetched", func(t *testing.T) {
		prev := azureSNPCRLGetter
		azureSNPCRLGetter = func(string) ([]byte, error) { return nil, assert.AnError }
		t.Cleanup(func() { azureSNPCRLGetter = prev })
		require.Error(t, azureSNPCheckRevocation(ch.vcek, ch.ask, ch.ark))
	})

	t.Run("rejects a stale (expired) CRL — replay defense", func(t *testing.T) {
		installCRL(t, arkSignedCRLUntil(t, ch, time.Now().Add(-time.Minute))) // NextUpdate in the past
		err := azureSNPCheckRevocation(ch.vcek, ch.ask, ch.ark)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stale")
	})

	t.Run("fails closed when the ASK has no CRL distribution point", func(t *testing.T) {
		installCRL(t, arkSignedCRL(t, ch))
		askNoDP := *ch.ask
		askNoDP.CRLDistributionPoints = nil
		require.Error(t, azureSNPCheckRevocation(ch.vcek, &askNoDP, ch.ark))
	})
}
