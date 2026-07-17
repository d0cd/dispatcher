package agent

import (
	"crypto/sha256"
)

// The binding function is shared by both ends of an attestation: the in-TEE agent
// writes the binding into its evidence (TPM qualifying data / eat_nonce), and the
// dispatcher-side verifier recomputes it to confirm the evidence commits to this
// run's nonce and the agent's channel key. It lives here in the leaf agent package
// so neither the per-cloud agents nor the verifiers need to import each other.

// MAABindingNonce is the value the guest passes to Azure MAA as the TPM-quote
// qualifying data: SHA-256 over the per-run nonce concatenated with the in-TEE
// channel key. SHA-256 (32 bytes) fits the TPM quote's qualifying-data limit
// (SHA-512 does not — the live TPM rejects it with TPM_RC_SIZE). MAA echoes it in
// x-ms-runtime.client-payload.nonce, binding this run + sealing key to the token.
func MAABindingNonce(nonce, channelKey []byte) []byte {
	h := sha256.New()
	h.Write(nonce)
	h.Write(channelKey)
	return h.Sum(nil)
}
