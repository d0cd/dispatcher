package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	legacytpm "github.com/google/go-tpm/legacy/tpm2"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

// Azure Confidential VM measured-boot attestation, verified directly the way
// Constellation does it — without MAA, so it isn't limited to MAA's 0–7 PCR subset
// or its secure-boot policy. The evidence chains:
//
//	SEV-SNP report (genuine AMD)  →  REPORT_DATA = SHA-256(runtime data)
//	runtime data (HCL)            →  carries the vTPM Attestation Key (HCLAkPub)
//	AK signs a TPM quote          →  over the PCRs, with our nonce as extraData
//
// so the vTPM's PCRs are trustworthy and PCR11 (the UKI carrying the agent) can be
// pinned — closing the agent-not-measured caveat. See docs/confidential-azure-uki.md.

// AzureSNPPolicy is what a measured Azure run demands of the evidence.
type AzureSNPPolicy struct {
	Roots []*x509.Certificate // pinned AMD ARK roots
	Nonce []byte              // per-run challenge (freshness)
	PCRs  map[int]string      // pinned PCR values (index → hex); PCR11 is the UKI
}

// verifyAzureSNP verifies the full chain and returns the PCR11 measurement + the
// bound channel key to seal to.
func verifyAzureSNP(ev agent.AzureSNPEvidence, p AzureSNPPolicy) (measurement string, channelKey []byte, err error) {
	// 1. Genuine SEV-SNP hardware: the report signature + cert chain to a pinned ARK.
	rep, err := parseSNPReport(ev.SNPReport)
	if err != nil {
		return "", nil, fmt.Errorf("parse snp report: %w", err)
	}
	vcek, err := x509.ParseCertificate(ev.VCEK)
	if err != nil {
		return "", nil, fmt.Errorf("parse vcek: %w", err)
	}
	ask, err := x509.ParseCertificate(ev.ASK)
	if err != nil {
		return "", nil, fmt.Errorf("parse ask: %w", err)
	}
	if err := verifySNPChain(vcek, ask, p.Roots); err != nil {
		return "", nil, fmt.Errorf("snp cert chain: %w", err)
	}
	if err := verifySNPSignature(rep, vcek); err != nil {
		return "", nil, fmt.Errorf("snp report signature: %w", err)
	}

	// 2. REPORT_DATA binds the runtime data (its SHA-256 in the first 32 bytes), so
	// the AK inside the runtime data is bound to this genuine hardware.
	rd := sha256.Sum256(ev.RuntimeData)
	if !bytes.Equal(rep.reportData[:32], rd[:]) {
		return "", nil, fmt.Errorf("snp report does not bind the runtime data (AK not hardware-bound)")
	}

	// 3. Extract the vTPM Attestation Key.
	ak, err := hclAkPub(ev.RuntimeData)
	if err != nil {
		return "", nil, err
	}

	// 4. The TPM quote must be signed by that AK.
	signed := sha256.Sum256(ev.Quote)
	if err := rsa.VerifyPKCS1v15(ak, crypto.SHA256, signed[:], ev.QuoteSig); err != nil {
		return "", nil, fmt.Errorf("quote signature: %w", err)
	}
	ad, err := legacytpm.DecodeAttestationData(ev.Quote)
	if err != nil {
		return "", nil, fmt.Errorf("parse quote: %w", err)
	}
	if ad.Type != legacytpm.TagAttestQuote || ad.AttestedQuoteInfo == nil {
		return "", nil, fmt.Errorf("attestation is not a PCR quote")
	}

	// 5. Freshness + channel binding: the quote's extraData is this run's binding.
	if len(p.Nonce) == 0 {
		return "", nil, fmt.Errorf("azure snp policy nonce missing — fail closed")
	}
	if !bytes.Equal(ad.ExtraData, agent.MAABindingNonce(p.Nonce, ev.ChannelKey)) {
		return "", nil, fmt.Errorf("quote extraData does not match this run's binding (replay/relay)")
	}

	// 6. The quote commits to a digest of the PCRs; recompute it from the provided
	// values so we know they are the genuine quoted PCRs, not attacker-substituted.
	if err := checkQuotedPCRs(ad.AttestedQuoteInfo, ev.PCRs); err != nil {
		return "", nil, err
	}

	// 7. Pin the measured PCRs (PCR11 = the UKI carrying the agent).
	if len(p.PCRs) == 0 {
		return "", nil, fmt.Errorf("azure snp policy pins no PCRs — fail closed")
	}
	for idx, want := range p.PCRs {
		got, ok := ev.PCRs[uint32(idx)]
		if !ok {
			return "", nil, fmt.Errorf("evidence does not carry pcr%d", idx)
		}
		if hex.EncodeToString(got) != want {
			return "", nil, fmt.Errorf("pcr%d does not match the pinned measured-image value", idx)
		}
	}
	return hex.EncodeToString(ev.PCRs[11]), ev.ChannelKey, nil
}

// azureSNPFetch obtains the direct-verification evidence bundle from the in-CVM
// agent, binding the verifier's per-run nonce. It needs a live vTPM, so it is the
// one part not unit-testable offline.
type azureSNPFetch func(ctx context.Context, nonce []byte) (agent.AzureSNPEvidence, error)

// azureSNPAttester verifies Azure confidential VMs directly (SEV-SNP + vTPM quote,
// no MAA). roots are the pinned AMD ARK roots; pcrs pins the measured-image PCRs.
type azureSNPAttester struct {
	roots []*x509.Certificate
	pcrs  map[int]string
	fetch azureSNPFetch
}

// NewAzureSNPAttester verifies an Azure confidential VM's measured boot directly
// from the agent endpoint: the SEV-SNP report + AK-signed vTPM quote, chained to
// the embedded AMD roots, pinning the known-good PCRs (PCR11 = the UKI + agent).
func NewAzureSNPAttester(pcrs map[int]string, baseURL string) Attester {
	return &azureSNPAttester{roots: amdRoots, pcrs: pcrs, fetch: endpointAzureSNPFetch(baseURL)}
}

func (a *azureSNPAttester) Verify(ctx context.Context, _ types.ConfidentialRequirement) (AttestationResult, error) {
	if a.fetch == nil {
		return AttestationResult{}, fmt.Errorf("azure snp attester has no evidence fetch wired")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return AttestationResult{}, fmt.Errorf("generate attestation nonce: %w", err)
	}
	ev, err := a.fetch(ctx, nonce)
	if err != nil {
		return AttestationResult{}, fmt.Errorf("fetch azure snp evidence: %w", err)
	}
	measurement, channelKey, err := verifyAzureSNP(ev, AzureSNPPolicy{Roots: a.roots, Nonce: nonce, PCRs: a.pcrs})
	if err != nil {
		return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: err.Error()}, nil
	}
	return AttestationResult{
		Verified:    true,
		Type:        "sev-snp",
		Measurement: measurement,
		Nonce:       hex.EncodeToString(nonce),
		Verdict:     "verified",
		ChannelKey:  channelKey,
	}, nil
}

// endpointAzureSNPFetch reads the evidence bundle (base64 JSON) from the in-CVM
// agent's /attest endpoint over the untrusted channel.
func endpointAzureSNPFetch(baseURL string) azureSNPFetch {
	return func(ctx context.Context, nonce []byte) (agent.AzureSNPEvidence, error) {
		token, _, err := agent.FetchAttestation(ctx, baseURL, nonce)
		if err != nil {
			return agent.AzureSNPEvidence{}, err
		}
		raw, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			return agent.AzureSNPEvidence{}, fmt.Errorf("decode evidence: %w", err)
		}
		var ev agent.AzureSNPEvidence
		if err := json.Unmarshal(raw, &ev); err != nil {
			return agent.AzureSNPEvidence{}, fmt.Errorf("parse evidence: %w", err)
		}
		return ev, nil
	}
}

// hclAkPub extracts the vTPM Attestation Key (the "HCLAkPub" RSA JWK) from the HCL
// runtime data.
func hclAkPub(runtimeData []byte) (*rsa.PublicKey, error) {
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(runtimeData, &doc); err != nil {
		return nil, fmt.Errorf("parse runtime data: %w", err)
	}
	for _, k := range doc.Keys {
		if k.Kid != "HCLAkPub" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("ak modulus: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("ak exponent: %w", err)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, fmt.Errorf("runtime data has no HCLAkPub key")
}

// checkQuotedPCRs recomputes the quote's PCR digest from the provided PCR values
// (SHA-256 over the selected PCRs in the selection's order) and checks it matches
// what the AK signed — so the provided PCRs are exactly the quoted ones.
func checkQuotedPCRs(qi *legacytpm.QuoteInfo, pcrs map[uint32][]byte) error {
	h := sha256.New()
	for _, idx := range qi.PCRSelection.PCRs {
		v, ok := pcrs[uint32(idx)]
		if !ok {
			return fmt.Errorf("quote selects pcr%d but evidence omits it", idx)
		}
		h.Write(v)
	}
	if !bytes.Equal(h.Sum(nil), qi.PCRDigest) {
		return fmt.Errorf("quoted PCR digest does not match the provided PCR values")
	}
	return nil
}
