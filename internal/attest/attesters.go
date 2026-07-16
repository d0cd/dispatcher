package attest

import "crypto"

// The attester constructors expose the provider verifiers over the in-TEE agent's
// /attest endpoint, keeping the fetch/evidence types internal to this package.
// dispatcher (the cloud adapters) just calls the right constructor + Verify.

// NewCSAttester verifies GCP Confidential Space tokens from the agent endpoint.
func NewCSAttester(keys map[string]crypto.PublicKey, baseURL string) Attester {
	return &csAttester{keys: keys, fetch: csEndpointFetch(baseURL)}
}
