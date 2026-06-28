package cloudvm

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/d0cd/dispatcher/internal/types"
)

// maaToken holds the subset of Microsoft Azure Attestation (MAA) claims the
// verifier enforces. MAA validates the hardware quote (SEV-SNP or TDX) and
// re-issues the result as a signed JWT, so trust reduces to the JWS signature
// plus these claims. Field names are MAA's published SEV-SNP claim schema.
type maaToken struct {
	AttestationType      string `json:"x-ms-attestation-type"`
	ComplianceStatus     string `json:"x-ms-compliance-status"`
	SNPLaunchMeasurement string `json:"x-ms-sevsnpvm-launchmeasurement"`
	SNPReportData        string `json:"x-ms-sevsnpvm-reportdata"`
	SNPIsDebuggable      bool   `json:"x-ms-sevsnpvm-is-debuggable"`
}

// verifyMAAToken verifies an MAA JWT against the trusted MAA signing keys and
// projects it onto provider-agnostic Claims. It enforces the signature, that
// the platform is an Azure-compliant CVM, and a recognized TEE type; the
// remaining policy (measurement allowlist, REPORT_DATA binding) is applyPolicy's
// job. TCB is left zero — MAA reports per-component SVNs rather than a single
// TCB, so minTCB enforcement on the MAA path is not yet wired (see gaps §6).
func verifyMAAToken(token string, keys map[string]crypto.PublicKey) (Claims, error) {
	payload, err := verifyJWS(token, keys)
	if err != nil {
		return Claims{}, fmt.Errorf("maa token signature: %w", err)
	}
	var t maaToken
	if err := json.Unmarshal(payload, &t); err != nil {
		return Claims{}, fmt.Errorf("parse maa claims: %w", err)
	}
	if t.ComplianceStatus != "azure-compliant-cvm" {
		return Claims{}, fmt.Errorf("maa compliance status %q is not azure-compliant-cvm", t.ComplianceStatus)
	}

	var teeType string
	switch t.AttestationType {
	case "sevsnpvm":
		teeType = "sev-snp"
	case "tdxvm":
		teeType = "tdx"
	default:
		return Claims{}, fmt.Errorf("maa attestation type %q is not a recognized confidential VM type", t.AttestationType)
	}

	reportData, err := hex.DecodeString(t.SNPReportData)
	if err != nil {
		return Claims{}, fmt.Errorf("maa report data is not hex: %w", err)
	}
	return Claims{
		TEEType:      teeType,
		Measurement:  t.SNPLaunchMeasurement,
		DebugEnabled: t.SNPIsDebuggable,
		ReportData:   reportData,
	}, nil
}

// maaEvidence is what the per-VM fetch returns: the MAA token the guest obtained
// (binding the verifier's nonce in its runtime data) and the in-TEE channel key.
type maaEvidence struct {
	token      string
	channelKey []byte
}

// maaFetch obtains an MAA token from a booted Azure confidential VM. It needs a
// live guest agent, so it is the one part not unit-testable offline.
type maaFetch func(ctx context.Context, vm *VMInfo, sshKeyPath, sshUser string, nonce []byte) (maaEvidence, error)

// azureAttester verifies Azure confidential VMs via MAA. keys are the trusted
// MAA signing keys (JWKS); isReady is false until a real fetch is wired, so the
// preflight fails closed before provisioning.
type azureAttester struct {
	keys    map[string]crypto.PublicKey
	fetch   maaFetch
	isReady bool
}

func (a *azureAttester) ready() bool { return a.isReady }

func (a *azureAttester) Verify(ctx context.Context, vm *VMInfo, sshKeyPath, sshUser string, req types.ConfidentialRequirement) (AttestationResult, error) {
	if a.fetch == nil {
		return AttestationResult{}, fmt.Errorf("azure attester has no evidence fetch wired")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return AttestationResult{}, fmt.Errorf("generate attestation nonce: %w", err)
	}

	ev, err := a.fetch(ctx, vm, sshKeyPath, sshUser, nonce)
	if err != nil {
		return AttestationResult{}, fmt.Errorf("fetch maa evidence: %w", err)
	}
	claims, err := verifyMAAToken(ev.token, a.keys)
	if err != nil {
		return AttestationResult{}, err
	}

	policy := VerificationPolicy{
		ExpectedType: req.Type,
		Measurements: req.Measurements,
		MinTCB:       req.MinTCB,
		Nonce:        nonce,
		ChannelKey:   ev.channelKey,
	}
	if err := applyPolicy(claims, policy); err != nil {
		return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: err.Error()}, nil
	}
	return AttestationResult{
		Verified:    true,
		Type:        claims.TEEType,
		Measurement: claims.Measurement,
		TCB:         claims.TCB,
		Nonce:       hex.EncodeToString(nonce),
		Verdict:     "verified",
	}, nil
}
