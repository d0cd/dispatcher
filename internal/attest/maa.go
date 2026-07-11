package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

// Azure Confidential VM attestation is a Microsoft Azure Attestation (MAA) JWT.
// The token has two parts, confirmed against a real captured token: the SEV-SNP
// hardware facts are NESTED under `x-ms-isolation-tee` (the isolation TEE), while
// the per-run binding rides in the top-level `x-ms-runtime.client-payload.nonce`
// (base64) — the value the guest supplied as the TPM-quote qualifying data, which
// MAA echoes. The vTPM SNP report's own REPORT_DATA is boot-fixed (the AK hash),
// so it cannot carry our nonce — the client-payload is the binding channel.
type maaToken struct {
	Iss     string `json:"iss"`
	Exp     int64  `json:"exp"`
	Nbf     int64  `json:"nbf"`
	Runtime struct {
		ClientPayload struct {
			Nonce string `json:"nonce"` // base64 of the nonce the guest supplied
		} `json:"client-payload"`
	} `json:"x-ms-runtime"`
	IsolationTEE struct {
		AttestationType   string `json:"x-ms-attestation-type"`  // "sevsnpvm"
		ComplianceStatus  string `json:"x-ms-compliance-status"` // "azure-compliant-cvm"
		LaunchMeasurement string `json:"x-ms-sevsnpvm-launchmeasurement"`
		IsDebuggable      bool   `json:"x-ms-sevsnpvm-is-debuggable"`
	} `json:"x-ms-isolation-tee"`
	// Measured-boot facts from the vTPM (the AMD SEV-SNP launch measurement above
	// covers only the CVM firmware, not the OS/agent). MAA attests PCRs 0–7; PCR4
	// (the boot application / UKI) is where a custom image's agent measurement lands.
	SecureBoot   bool              `json:"secureboot"`
	AttestedPCRs map[string]string `json:"x-ms-azurevm-attested-pcr-values"`
}

// MAAPolicy is what an Azure confidential run demands of an MAA token.
type MAAPolicy struct {
	Issuer       string   // pinned MAA instance issuer (required)
	Nonce        []byte   // expected client-payload nonce (= agent.MAABindingNonce)
	Measurements []string // exact allowlist of accepted launch measurements (hex)
	// PCRs pins expected vTPM PCR values (index → base64 SHA-256) that MAA must
	// attest. Pinning PCR4 (the boot application / UKI carrying the agent) is what
	// closes the agent-not-measured caveat; empty skips measured-boot enforcement.
	PCRs map[int]string
	// RequireSecureBoot rejects a token unless the vTPM reports secure boot on.
	RequireSecureBoot bool
}

// verifyMAAToken verifies an Azure MAA CVM token against the pinned MAA signing
// keys and enforces: the pinned issuer; freshness (exp/nbf plus the per-run nonce
// echoed in client-payload); and, from the nested isolation TEE, a genuine
// azure-compliant SEV-SNP CVM with debug off and its launch measurement on the
// allowlist. Returns the attested launch measurement on success.
func verifyMAAToken(token string, keys map[string]crypto.PublicKey, p MAAPolicy) (string, error) {
	payload, err := verifyJWS(token, keys)
	if err != nil {
		return "", fmt.Errorf("maa token signature: %w", err)
	}
	var t maaToken
	if err := json.Unmarshal(payload, &t); err != nil {
		return "", fmt.Errorf("parse maa token: %w", err)
	}

	if p.Issuer == "" {
		return "", fmt.Errorf("maa policy issuer must be set (pin the MAA instance)")
	}
	if t.Iss != p.Issuer {
		return "", fmt.Errorf("maa token issuer %q is not the pinned MAA instance %q", t.Iss, p.Issuer)
	}
	now := time.Now().Unix()
	if t.Exp == 0 || now >= t.Exp {
		return "", fmt.Errorf("maa token is missing exp or has expired")
	}
	if t.Nbf != 0 && now < t.Nbf {
		return "", fmt.Errorf("maa token is not yet valid (nbf)")
	}

	// Freshness/anti-replay + channel-key binding: the echoed client-payload
	// nonce must equal our expected value (SHA-256(nonce ‖ channelKey)).
	if len(p.Nonce) == 0 {
		return "", fmt.Errorf("maa policy nonce missing — fail closed")
	}
	got, err := base64.StdEncoding.DecodeString(t.Runtime.ClientPayload.Nonce)
	if err != nil {
		return "", fmt.Errorf("maa client-payload nonce is not base64: %w", err)
	}
	if !bytes.Equal(got, p.Nonce) {
		return "", fmt.Errorf("maa token client-payload nonce does not bind this run's nonce and channel key (replay/relay)")
	}

	// The SEV-SNP facts live in the nested isolation TEE.
	tee := t.IsolationTEE
	if !strings.EqualFold(tee.AttestationType, "sevsnpvm") {
		return "", fmt.Errorf("maa isolation-tee attestation type %q is not sevsnpvm", tee.AttestationType)
	}
	if !strings.EqualFold(tee.ComplianceStatus, "azure-compliant-cvm") {
		return "", fmt.Errorf("maa compliance status %q is not azure-compliant-cvm", tee.ComplianceStatus)
	}
	if tee.IsDebuggable {
		return "", fmt.Errorf("maa token reports a debuggable VM (debug must be off)")
	}
	if !measurementAllowed(tee.LaunchMeasurement, p.Measurements) {
		return "", fmt.Errorf("maa launch measurement %q is not on the allowlist", tee.LaunchMeasurement)
	}

	// Measured-boot enforcement (closes the agent-not-measured caveat): the SEV-SNP
	// launch measurement above proves genuine Azure CVM firmware but not the OS or
	// agent. The pinned PCRs — chiefly PCR4, the boot application (UKI) carrying the
	// agent — must match what the vTPM attested, with secure boot on when required.
	if p.RequireSecureBoot && !t.SecureBoot {
		return "", fmt.Errorf("maa token reports secure boot off (a measured image requires it on)")
	}
	for idx, want := range p.PCRs {
		key := fmt.Sprintf("pcr%d", idx)
		got, ok := t.AttestedPCRs[key]
		if !ok {
			return "", fmt.Errorf("maa token does not attest %s (needed to pin the measured agent)", key)
		}
		if got != want {
			return "", fmt.Errorf("maa %s does not match the pinned measured-image value", key)
		}
	}
	return tee.LaunchMeasurement, nil
}

// maaEvidence is what the per-VM fetch returns: the MAA token the guest obtained
// (its client-payload nonce binding SHA-256(nonce ‖ channelKey)) and the in-TEE
// channel key dispatcher seals to.
type maaEvidence struct {
	token      string
	channelKey []byte
}

// maaFetch obtains an MAA token from a booted Azure confidential VM. The guest
// generates the channel key, passes SHA-256(nonce ‖ channelKey) to MAA as the
// TPM-quote qualifying data, and returns the token + channel key. It needs a live
// vTPM, so it is the one part not unit-testable offline.
type maaFetch func(ctx context.Context, nonce []byte) (maaEvidence, error)

// MAAMeasuredBoot pins the vTPM measured-boot state a custom measured image must
// present: PCR values (index → base64 SHA-256) MAA must attest, and whether secure
// boot must be on. Pinning PCR4 (the boot application / UKI carrying the agent) is
// what closes the agent-not-measured caveat. The zero value disables measured-boot
// enforcement — the pre-measured-image behavior (firmware-only attestation).
type MAAMeasuredBoot struct {
	PCRs              map[int]string
	RequireSecureBoot bool
}

// azureAttester verifies Azure confidential VMs via MAA. keys are the trusted MAA
// signing keys (the instance's /certs JWKS); issuer is the pinned MAA instance;
// mb optionally pins measured-boot PCRs; isReady is false until a real fetch is
// wired, so the preflight fails closed before provisioning.
type azureAttester struct {
	keys    map[string]crypto.PublicKey
	issuer  string
	mb      MAAMeasuredBoot
	fetch   maaFetch
	isReady bool
}

func (a *azureAttester) ready() bool { return a.isReady }

func (a *azureAttester) Verify(ctx context.Context, req types.ConfidentialRequirement) (AttestationResult, error) {
	if a.fetch == nil {
		return AttestationResult{}, fmt.Errorf("azure attester has no evidence fetch wired")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return AttestationResult{}, fmt.Errorf("generate attestation nonce: %w", err)
	}

	ev, err := a.fetch(ctx, nonce)
	if err != nil {
		return AttestationResult{}, fmt.Errorf("fetch maa evidence: %w", err)
	}

	measurement, err := verifyMAAToken(ev.token, a.keys, MAAPolicy{
		Issuer:            a.issuer,
		Nonce:             agent.MAABindingNonce(nonce, ev.channelKey),
		Measurements:      req.Measurements,
		PCRs:              a.mb.PCRs,
		RequireSecureBoot: a.mb.RequireSecureBoot,
	})
	if err != nil {
		// A token that fails verification is a verdict (abort the run), not a
		// fetch fault — surface the reason.
		return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: err.Error()}, nil
	}
	return AttestationResult{
		Verified:    true,
		Type:        "sev-snp",
		Measurement: measurement,
		Nonce:       hex.EncodeToString(nonce),
		Verdict:     "verified",
		ChannelKey:  ev.channelKey, // verified-bound; the adapter seals to it
	}, nil
}
