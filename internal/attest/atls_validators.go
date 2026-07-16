package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/attest/atls"
)

// These adapt the per-cloud verify cores to atls.Validator: the evidence arrives
// from the TLS exchange, and the run binding is checked against bindData (the
// session key||exporter commitment) instead of a channel key fetched over the
// untrusted endpoint. The verify logic is unchanged — bindData just takes the
// slot the channel key used to.

// NitroValidator verifies a Nitro COSE document from the aTLS exchange and that
// it is bound to this session's bindData + nonce.
func NitroValidator(roots *x509.CertPool, pcrs map[int]string) atls.Validator {
	return validatorFunc(func(_ context.Context, evidence, bindData, nonce []byte) error {
		cose, err := base64.StdEncoding.DecodeString(string(evidence))
		if err != nil {
			return fmt.Errorf("decode nitro evidence: %w", err)
		}
		_, bound, err := verifyNitroDoc(cose, roots, NitroPolicy{Nonce: nonce, PCRs: pcrs})
		if err != nil {
			return err
		}
		if !bytes.Equal(bound, bindData) {
			return fmt.Errorf("nitro attestation is not bound to this aTLS session")
		}
		return nil
	})
}

// CSValidator verifies a Confidential Space token from the aTLS exchange; the
// token's eat_nonce must commit to this session's bindData + nonce.
func CSValidator(keys map[string]crypto.PublicKey, imageDigests []string, expectedType string) atls.Validator {
	return validatorFunc(func(_ context.Context, evidence, bindData, nonce []byte) error {
		_, _, err := verifyCSToken(string(evidence), keys, CSPolicy{
			Nonce: nonce, ImageDigests: imageDigests, ChannelKey: bindData, ExpectedType: expectedType,
		})
		return err
	})
}

// AzureSNPValidator verifies an azure-snp evidence bundle from the aTLS exchange;
// its SEV-SNP REPORT_DATA and vTPM quote must commit to this session's bindData +
// nonce. The channel-supplied key in the bundle is ignored — the session binding
// is authoritative.
func AzureSNPValidator(roots []*x509.Certificate, pcrs map[int]string, minTCB uint64) atls.Validator {
	return validatorFunc(func(_ context.Context, evidence, bindData, nonce []byte) error {
		ev, err := parseAzureSNPEvidence(evidence)
		if err != nil {
			return err
		}
		ev.ChannelKey = bindData // trust the session binding, not the channel-supplied key
		_, _, err = verifyAzureSNP(ev, AzureSNPPolicy{Roots: roots, Nonce: nonce, PCRs: pcrs, MinTCB: minTCB})
		return err
	})
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

type validatorFunc func(ctx context.Context, evidence, bindData, nonce []byte) error

func (f validatorFunc) Validate(ctx context.Context, evidence, bindData, nonce []byte) error {
	return f(ctx, evidence, bindData, nonce)
}
