package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// AttestValidator adapts a per-cloud verify core to atls.Validator: the evidence
// arrives from the TLS exchange, and the run binding is checked against bindData
// (the session key||exporter commitment) instead of a channel key fetched over the
// untrusted endpoint. It records the verified attestation verdict so the adapter
// can persist it for the run's audit trail (R13/G5). The verify logic is unchanged
// — bindData just takes the slot the channel key used to.
type AttestValidator struct {
	verify func(evidence, bindData, nonce []byte) (AttestationResult, error)
	Result AttestationResult
}

func (v *AttestValidator) Validate(_ context.Context, evidence, bindData, nonce []byte) error {
	res, err := v.verify(evidence, bindData, nonce)
	if err != nil {
		return err
	}
	if !res.Verified {
		return fmt.Errorf("attestation rejected: %s", res.Verdict)
	}
	v.Result = res
	return nil
}

// CSValidator verifies a Confidential Space token from the aTLS exchange; the
// token's eat_nonce must commit to this session's bindData + nonce. The CS token
// carries no reported TCB, so a configured minTCB floor cannot be enforced — the
// validator fails closed rather than silently ignore it.
func CSValidator(keys map[string]crypto.PublicKey, imageDigests []string, expectedType string, minTCB uint64) *AttestValidator {
	return &AttestValidator{verify: func(evidence, bindData, nonce []byte) (AttestationResult, error) {
		if minTCB > 0 {
			return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: "minTCB cannot be enforced on the GCP Confidential Space path (the attestation token carries no reported TCB)"}, nil
		}
		digest, teeType, err := verifyCSToken(string(evidence), keys, CSPolicy{
			Nonce: nonce, ImageDigests: imageDigests, ChannelKey: bindData, ExpectedType: expectedType,
		})
		if err != nil {
			return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: err.Error()}, nil
		}
		return AttestationResult{Verified: true, Type: teeType, Measurement: digest, Nonce: hex.EncodeToString(nonce), Verdict: "verified"}, nil
	}}
}

// NitroValidator verifies a Nitro COSE document from the aTLS exchange and that it
// is bound to this session's bindData + nonce.
func NitroValidator(roots *x509.CertPool, pcrs map[int]string) *AttestValidator {
	return &AttestValidator{verify: func(evidence, bindData, nonce []byte) (AttestationResult, error) {
		cose, err := base64.StdEncoding.DecodeString(string(evidence))
		if err != nil {
			return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: "decode nitro evidence: " + err.Error()}, nil
		}
		measurement, bound, err := verifyNitroDoc(cose, roots, NitroPolicy{Nonce: nonce, PCRs: pcrs})
		if err != nil {
			return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: err.Error()}, nil
		}
		if !bytes.Equal(bound, bindData) {
			return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: "nitro attestation is not bound to this aTLS session"}, nil
		}
		return AttestationResult{Verified: true, Type: "nitro", Measurement: measurement, Nonce: hex.EncodeToString(nonce), Verdict: "verified"}, nil
	}}
}

// AzureSNPValidator verifies an azure-snp evidence bundle from the aTLS exchange;
// its SEV-SNP REPORT_DATA and vTPM quote must commit to this session's bindData +
// nonce. The channel-supplied key in the bundle is ignored — the session binding
// is authoritative.
func AzureSNPValidator(roots []*x509.Certificate, pcrs map[int]string, minTCB uint64) *AttestValidator {
	return &AttestValidator{verify: func(evidence, bindData, nonce []byte) (AttestationResult, error) {
		ev, err := parseAzureSNPEvidence(evidence)
		if err != nil {
			return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: err.Error()}, nil
		}
		ev.ChannelKey = bindData // trust the session binding, not the channel-supplied key
		measurement, _, err := verifyAzureSNP(ev, AzureSNPPolicy{Roots: roots, Nonce: nonce, PCRs: pcrs, MinTCB: minTCB})
		if err != nil {
			return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: err.Error()}, nil
		}
		return AttestationResult{Verified: true, Type: "sev-snp", Measurement: measurement, Nonce: hex.EncodeToString(nonce), Verdict: "verified"}, nil
	}}
}

// NitroValidatorPinned builds a NitroValidator against the pinned AWS Nitro root
// (the production trust anchor), mirroring NewAWSNitroAttester.
func NitroValidatorPinned(pcrs map[int]string) *AttestValidator {
	return NitroValidator(awsNitroRoots, pcrs)
}

// AzureSNPValidatorPinned builds an AzureSNPValidator against the pinned AMD ARK
// roots, mirroring NewAzureSNPAttester.
func AzureSNPValidatorPinned(pcrs map[int]string, minTCB uint64) *AttestValidator {
	return AzureSNPValidator(amdRoots, pcrs, minTCB)
}

// parseAzureSNPEvidence accepts either raw JSON or the base64(JSON) the producer
// emits.
func parseAzureSNPEvidence(evidence []byte) (agent.AzureSNPEvidence, error) {
	var ev agent.AzureSNPEvidence
	if json.Unmarshal(evidence, &ev) == nil {
		return ev, nil
	}
	raw, err := base64.StdEncoding.DecodeString(string(evidence))
	if err != nil {
		return agent.AzureSNPEvidence{}, fmt.Errorf("parse azure snp evidence: %w", err)
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		return agent.AzureSNPEvidence{}, fmt.Errorf("parse azure snp evidence: %w", err)
	}
	return ev, nil
}
