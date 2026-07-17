package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// AttestFunc obtains an attestation token that binds this run's nonce and the
// agent's aTLS session commitment (bindData). It is the one provider-specific part
// of the agent: GCP Confidential Space fetches a CS token from the teeserver
// socket; Azure fetches an SNP+vTPM quote; Nitro asks the NSM. Everything
// downstream (the attested TLS session, run, result) is provider-agnostic.
type AttestFunc func(ctx context.Context, runNonce, bindData []byte) (string, error)

// csAttestFunc binds [runNonce, SHA-256(bindData)] into a Confidential Space token
// from the container-launcher teeserver socket.
func csAttestFunc(socket, audience string) AttestFunc {
	return func(ctx context.Context, runNonce, bindData []byte) (string, error) {
		sum := sha256.Sum256(bindData)
		nonces := []string{hex.EncodeToString(runNonce), hex.EncodeToString(sum[:])}
		return requestAttestationToken(ctx, socket, tokenRequest{Audience: audience, Nonces: nonces})
	}
}
