package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	legacytpm "github.com/google/go-tpm/legacy/tpm2"

	"github.com/d0cd/dispatcher/internal/attest/agent"
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
	Roots  []*x509.Certificate // pinned AMD ARK roots
	Nonce  []byte              // per-run challenge (freshness)
	PCRs   map[int]string      // pinned PCR values (index → hex); PCR11 is the UKI
	MinTCB uint64              // minimum acceptable reported TCB (0 = no floor)
}

// verifyAzureSNP verifies the full chain against a policy that pins the measured
// PCRs, returning the PCR11 measurement + the bound channel key to seal to.
func verifyAzureSNP(ev agent.AzureSNPEvidence, p AzureSNPPolicy) (measurement string, channelKey []byte, err error) {
	pcrs, quoted, channelKey, err := verifyAzureSNPEvidence(ev, p.Roots, p.Nonce, p.MinTCB)
	if err != nil {
		return "", nil, err
	}
	// Pin the measured PCRs (PCR11 = the UKI carrying the agent). Each pinned PCR
	// must be one the quote actually covered — a value in the evidence map that the
	// AK never signed is unverified, so it can't be trusted even if it equals the pin.
	if len(p.PCRs) == 0 {
		return "", nil, fmt.Errorf("azure snp policy pins no PCRs — fail closed")
	}
	for idx, want := range p.PCRs {
		if !slices.Contains(quoted, idx) {
			return "", nil, fmt.Errorf("pinned pcr%d was not covered by the signed quote", idx)
		}
		got, ok := pcrs[uint32(idx)]
		if !ok {
			return "", nil, fmt.Errorf("evidence does not carry pcr%d", idx)
		}
		if hex.EncodeToString(got) != want {
			return "", nil, fmt.Errorf("pcr%d does not match the pinned measured-image value", idx)
		}
	}
	return hex.EncodeToString(pcrs[11]), channelKey, nil
}

// verifyAzureSNPEvidence performs the genuineness, freshness, and quote-binding
// checks — everything except comparing to a pinned PCR set — and returns the
// verified PCR values, the PCR indices the quote actually covers, and the bound
// channel key. Both the run-path attester (which compares to a pin) and capture
// (which derives the value to pin) build on this, so a measurement is never pinned
// or accepted without the same cryptographic proof.
func verifyAzureSNPEvidence(ev agent.AzureSNPEvidence, roots []*x509.Certificate, nonce []byte, minTCB uint64) (pcrs map[uint32][]byte, quoted []int, channelKey []byte, err error) {
	// 1. Genuine SEV-SNP hardware: the report signature + cert chain to a pinned ARK.
	rep, err := parseSNPReport(ev.SNPReport)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse snp report: %w", err)
	}
	vcek, err := x509.ParseCertificate(ev.VCEK)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse vcek: %w", err)
	}
	ask, err := x509.ParseCertificate(ev.ASK)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse ask: %w", err)
	}
	if err := verifySNPChain(vcek, ask, roots); err != nil {
		return nil, nil, nil, fmt.Errorf("snp cert chain: %w", err)
	}
	if err := verifySNPSignature(rep, vcek); err != nil {
		return nil, nil, nil, fmt.Errorf("snp report signature: %w", err)
	}
	if err := azureSNPCheckRevocation(vcek, ask, roots); err != nil {
		return nil, nil, nil, err
	}

	// 1b. Guest policy + TCB: a
	// DEBUG guest lets the host read/write guest memory and forge the vTPM AK, and
	// MIGRATE_MA permits a migration agent — both defeat the whole guarantee. A
	// reported TCB below the operator minimum is running known-vulnerable firmware.
	if rep.policy&snpPolicyDebug != 0 {
		return nil, nil, nil, fmt.Errorf("snp report: debug is enabled (policy.debug must be off)")
	}
	if rep.policy&snpPolicyMigrateMA != 0 {
		return nil, nil, nil, fmt.Errorf("snp report: migration agent is enabled (must be off)")
	}
	if !tcbComponentsGTE(rep.reportedTCB, minTCB) {
		return nil, nil, nil, fmt.Errorf("snp report: reported TCB %d has a component below the minimum %d", rep.reportedTCB, minTCB)
	}

	// 2. REPORT_DATA binds the runtime data (its SHA-256 in the first 32 bytes), so
	// the AK inside the runtime data is bound to this genuine hardware.
	rd := sha256.Sum256(ev.RuntimeData)
	if !bytes.Equal(rep.reportData[:32], rd[:]) {
		return nil, nil, nil, fmt.Errorf("snp report does not bind the runtime data (AK not hardware-bound)")
	}

	// 3. Extract the vTPM Attestation Key.
	ak, err := hclAkPub(ev.RuntimeData)
	if err != nil {
		return nil, nil, nil, err
	}

	// 4. The TPM quote must be signed by that AK.
	signed := sha256.Sum256(ev.Quote)
	if err := rsa.VerifyPKCS1v15(ak, crypto.SHA256, signed[:], ev.QuoteSig); err != nil {
		return nil, nil, nil, fmt.Errorf("quote signature: %w", err)
	}
	ad, err := legacytpm.DecodeAttestationData(ev.Quote)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse quote: %w", err)
	}
	if ad.Type != legacytpm.TagAttestQuote || ad.AttestedQuoteInfo == nil {
		return nil, nil, nil, fmt.Errorf("attestation is not a PCR quote")
	}

	// 5. Freshness + channel binding: the quote's extraData is this run's binding.
	if len(nonce) != 32 {
		return nil, nil, nil, fmt.Errorf("azure snp nonce must be exactly 32 bytes, got %d — fail closed", len(nonce))
	}
	if !bytes.Equal(ad.ExtraData, agent.MAABindingNonce(nonce, ev.ChannelKey)) {
		return nil, nil, nil, fmt.Errorf("quote extraData does not match this run's binding (replay/relay)")
	}

	// 6. The quote commits to a digest of the PCRs; recompute it from the provided
	// values so we know they are the genuine quoted PCRs, not attacker-substituted.
	if err := checkQuotedPCRs(ad.AttestedQuoteInfo, ev.PCRs); err != nil {
		return nil, nil, nil, err
	}
	return ev.PCRs, ad.AttestedQuoteInfo.PCRSelection.PCRs, ev.ChannelKey, nil
}

// CaptureAzureSNPMeasurement attests a booted measured CVM over aTLS and returns
// its PCR11 only after full cryptographic verification (genuine SEV-SNP hardware,
// AK-bound quote committed to the aTLS session, and PCR11 actually covered by the
// signed quote) against the pinned AMD roots. It derives the measurement to pin
// rather than trusting whatever the endpoint returns, so a compromised host or a
// session MITM cannot poison the pinned measurement.
func CaptureAzureSNPMeasurement(ctx context.Context, endpoint string) (string, error) {
	c := &azureSNPCapture{roots: amdRoots}
	if err := agent.AttestOverATLS(ctx, strings.TrimPrefix(endpoint, "http://"), c); err != nil {
		return "", fmt.Errorf("capture azure snp measurement over aTLS: %w", err)
	}
	return c.pcr11, nil
}

// azureSNPCapture is a capture-only atls.Validator: it verifies the evidence
// against the pinned AMD roots and records the hardware-attested PCR11 to pin.
// bindData is the aTLS session commitment the quote must bind to (authoritative
// over the channel-supplied key).
type azureSNPCapture struct {
	roots []*x509.Certificate
	pcr11 string
}

func (c *azureSNPCapture) Validate(_ context.Context, evidence, bindData, nonce []byte) error {
	ev, err := parseAzureSNPEvidence(evidence)
	if err != nil {
		return err
	}
	ev.ChannelKey = bindData
	pcr11, err := captureAzureSNPPCR11(ev, c.roots, nonce)
	if err != nil {
		return err
	}
	c.pcr11 = pcr11
	return nil
}

// captureAzureSNPPCR11 verifies the evidence and returns its quoted PCR11.
func captureAzureSNPPCR11(ev agent.AzureSNPEvidence, roots []*x509.Certificate, nonce []byte) (string, error) {
	// minTCB=0 at capture (establishing the baseline), but debug/migrate are still
	// rejected so a debuggable VM can't poison the pinned PCR11.
	pcrs, quoted, _, err := verifyAzureSNPEvidence(ev, roots, nonce, 0)
	if err != nil {
		return "", fmt.Errorf("verify azure snp evidence: %w", err)
	}
	if !slices.Contains(quoted, 11) {
		return "", fmt.Errorf("evidence quote does not cover pcr11 — refusing to capture an unmeasured value")
	}
	v, ok := pcrs[11]
	if !ok {
		return "", fmt.Errorf("verified evidence carries no pcr11")
	}
	return hex.EncodeToString(v), nil
}

// azureSNPCRLGetter fetches a CRL by URL. A package-level seam so tests run
// offline; production fetches the ARK-signed CRL from AMD KDS.
var azureSNPCRLGetter = func(url string) ([]byte, error) {
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL %s: %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// azureSNPCheckRevocation fails closed if the VCEK or its ASK has been revoked by
// AMD. The CRL is fetched from the ASK's distribution point (AMD KDS) and must
// itself be signed by a pinned ARK. A missing distribution point or an
// unreachable/invalid CRL is a rejection, not a pass — an attacker who can block
// KDS must not be able to bypass revocation.
func azureSNPCheckRevocation(vcek, ask *x509.Certificate, roots []*x509.Certificate) error {
	if len(ask.CRLDistributionPoints) == 0 {
		return fmt.Errorf("snp revocation: ASK has no CRL distribution point")
	}
	body, err := azureSNPCRLGetter(ask.CRLDistributionPoints[0])
	if err != nil {
		return fmt.Errorf("snp revocation: fetch ASK CRL: %w", err)
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return fmt.Errorf("snp revocation: parse ASK CRL: %w", err)
	}
	signed := false
	for _, root := range roots {
		if crl.CheckSignatureFrom(root) == nil {
			signed = true
			break
		}
	}
	if !signed {
		return fmt.Errorf("snp revocation: ASK CRL is not signed by a pinned AMD root")
	}
	// Freshness: the KDS transport is untrusted, so an attacker who can serve the
	// CRL can also replay an older, still-validly-signed pre-revocation list. A
	// stale/expired NextUpdate must be rejected (fail closed) or replay defeats
	// revocation.
	if crl.NextUpdate.IsZero() || time.Now().After(crl.NextUpdate) {
		return fmt.Errorf("snp revocation: ASK CRL is stale (nextUpdate %s) — refusing a possibly-replayed pre-revocation list", crl.NextUpdate.Format(time.RFC3339))
	}
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(vcek.SerialNumber) == 0 {
			return fmt.Errorf("snp revocation: the VCEK has been revoked by AMD")
		}
		if e.SerialNumber.Cmp(ask.SerialNumber) == 0 {
			return fmt.Errorf("snp revocation: the ASK has been revoked by AMD")
		}
	}
	return nil
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
