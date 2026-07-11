package attest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
)

// GCP Confidential Space attestation is a Google-signed OIDC/EAT token — not a
// raw SEV-SNP report. The measured Confidential Space runtime attests the
// workload CONTAINER's image digest and binds a caller-supplied nonce via
// `eat_nonce`, so trust reduces to the JWS signature (Google's JWKS) plus these
// claims. This is the "vendor" path for GCP (see confidential-attestation-plan.md):
// no raw AMD chain, no per-image launch-measurement capture — the attested
// identity is the container image digest, allowlisted like a measurement.
const csIssuer = "https://confidentialcomputing.googleapis.com"

// csEATNonce decodes `eat_nonce`, which Confidential Space emits as either a
// single string or an array of strings.
type csEATNonce []string

func (n *csEATNonce) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*n = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*n = many
	return nil
}

// csToken is the subset of a Confidential Space attestation token the verifier
// enforces.
type csToken struct {
	Iss      string     `json:"iss"`
	Exp      int64      `json:"exp"`
	Nbf      int64      `json:"nbf"`
	EatNonce csEATNonce `json:"eat_nonce"`
	HwModel  string     `json:"hwmodel"` // e.g. "GCP_AMD_SEV"
	SwName   string     `json:"swname"`  // "CONFIDENTIAL_SPACE"
	DbgStat  string     `json:"dbgstat"` // "disabled-since-boot"
	Submods  struct {
		Container struct {
			ImageDigest    string `json:"image_digest"`    // sha256:...
			ImageReference string `json:"image_reference"` // registry ref
		} `json:"container"`
	} `json:"submods"`
}

// CSPolicy is what a Confidential Space run demands of the attestation token.
type CSPolicy struct {
	Nonce        []byte   // per-run challenge; its hex must appear in eat_nonce
	ImageDigests []string // exact allowlist of accepted container image digests
	// ChannelKey, when non-nil, is the in-TEE sealing public key the token must
	// commit to: hex(SHA-256(ChannelKey)) must also appear in eat_nonce. This
	// binds the key dispatcher seals secrets to (R9) to the attested container,
	// so a relay host can't substitute its own key. Nil on the verify-only path.
	ChannelKey []byte
}

// verifyCSToken verifies a GCP Confidential Space attestation token against
// Google's signing keys and enforces: the Google issuer; freshness (exp/nbf plus
// the per-run nonce echoed in eat_nonce); a genuine AMD-SEV Confidential Space
// runtime with debug disabled; and the workload container digest on the
// allowlist. Returns the attested container image digest on success.
func verifyCSToken(token string, keys map[string]crypto.PublicKey, p CSPolicy) (string, error) {
	payload, err := verifyJWS(token, keys)
	if err != nil {
		return "", fmt.Errorf("cs token signature: %w", err)
	}
	var t csToken
	if err := json.Unmarshal(payload, &t); err != nil {
		return "", fmt.Errorf("parse cs token: %w", err)
	}

	if t.Iss != csIssuer {
		return "", fmt.Errorf("cs token issuer %q is not the Confidential Space service %q", t.Iss, csIssuer)
	}
	now := time.Now().Unix()
	if t.Exp == 0 || now >= t.Exp {
		return "", fmt.Errorf("cs token is missing exp or has expired")
	}
	if t.Nbf != 0 && now < t.Nbf {
		return "", fmt.Errorf("cs token is not yet valid (nbf)")
	}

	// Freshness/anti-replay: our per-run nonce (hex) must be one of the token's
	// eat_nonce values. This replaces the SNP REPORT_DATA binding on the CS path.
	if len(p.Nonce) != 32 {
		return "", fmt.Errorf("cs policy nonce must be exactly 32 bytes, got %d", len(p.Nonce))
	}
	if !containsFold(t.EatNonce, hex.EncodeToString(p.Nonce)) {
		return "", fmt.Errorf("cs token eat_nonce does not contain this run's nonce (replay/relay)")
	}

	// Bind the sealing key to the attested container: eat_nonce must also commit
	// to SHA-256(channel key). Without this a relay host could hand dispatcher its
	// own key and read the sealed secrets. Skipped on the verify-only path.
	if len(p.ChannelKey) > 0 {
		sum := sha256.Sum256(p.ChannelKey)
		if !containsFold(t.EatNonce, hex.EncodeToString(sum[:])) {
			return "", fmt.Errorf("cs token eat_nonce does not commit to the channel key (unbound sealing key)")
		}
	}

	if !strings.EqualFold(t.SwName, "CONFIDENTIAL_SPACE") {
		return "", fmt.Errorf("cs token swname %q is not CONFIDENTIAL_SPACE", t.SwName)
	}
	if !strings.Contains(strings.ToUpper(t.HwModel), "SEV") {
		return "", fmt.Errorf("cs token hwmodel %q is not an AMD SEV confidential platform", t.HwModel)
	}
	if !strings.EqualFold(t.DbgStat, "disabled-since-boot") {
		return "", fmt.Errorf("cs token dbgstat %q — debug must be disabled-since-boot", t.DbgStat)
	}

	// The container image digest is the attested workload identity — the CS
	// analog of a launch measurement. Exact allowlist, fail closed when empty.
	digest := t.Submods.Container.ImageDigest
	if !measurementAllowed(digest, p.ImageDigests) {
		return "", fmt.Errorf("cs container image digest %q is not on the allowlist", digest)
	}
	return digest, nil
}

func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// csEvidence is what the Confidential Space fetch returns: the Google-signed
// attestation token (binding the verifier's nonce in eat_nonce) and the in-TEE
// channel public key secrets are later sealed to.
type csEvidence struct {
	token      string
	channelKey []byte
}

// csFetch obtains a Confidential Space attestation token from a booted CS VM
// (via the container-launcher teeserver socket), passing the per-run nonce. It
// needs the measured CS runtime, so it is the one part not unit-testable offline.
type csFetch func(ctx context.Context, nonce []byte) (csEvidence, error)

// csAttester verifies GCP Confidential Space attestation tokens. keys are the
// trusted Google signing keys (JWKS); isReady is false until a real fetch is
// wired, so the preflight fails closed before provisioning. The run's
// ConfidentialRequirement.Measurements carries the accepted container image
// digests (the CS analog of a launch-measurement allowlist).
type csAttester struct {
	keys    map[string]crypto.PublicKey
	fetch   csFetch
	isReady bool
}

func (a *csAttester) ready() bool { return a.isReady }

func (a *csAttester) Verify(ctx context.Context, req types.ConfidentialRequirement) (AttestationResult, error) {
	if a.fetch == nil {
		return AttestationResult{}, fmt.Errorf("cs attester has no evidence fetch wired")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return AttestationResult{}, fmt.Errorf("generate attestation nonce: %w", err)
	}
	ev, err := a.fetch(ctx, nonce)
	if err != nil {
		return AttestationResult{}, fmt.Errorf("fetch cs evidence: %w", err)
	}
	// When the agent supplies a channel key (sealed path), the policy binds it;
	// a nil key (verify-only) leaves the binding off.
	digest, err := verifyCSToken(ev.token, a.keys, CSPolicy{Nonce: nonce, ImageDigests: req.Measurements, ChannelKey: ev.channelKey})
	if err != nil {
		// A token that fails verification is a verdict (abort the run), not a
		// fetch fault — surface the reason.
		return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: err.Error()}, nil
	}
	return AttestationResult{
		Verified:    true,
		Type:        "sev-snp",
		Measurement: digest, // the attested container image digest
		Nonce:       hex.EncodeToString(nonce),
		Verdict:     "verified",
		ChannelKey:  ev.channelKey, // verified-bound; the adapter seals to it
	}, nil
}
