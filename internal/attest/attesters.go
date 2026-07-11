package attest

import (
	"context"
	"crypto"
)

// The attester constructors expose the provider verifiers over the in-TEE agent's
// /attest endpoint, keeping the fetch/evidence types internal to this package.
// dispatcher (the cloud adapters) just calls the right constructor + Verify.

// NewCSAttester verifies GCP Confidential Space tokens from the agent endpoint.
func NewCSAttester(keys map[string]crypto.PublicKey, baseURL string) Attester {
	return &csAttester{keys: keys, isReady: true, fetch: csEndpointFetch(baseURL)}
}

// NewAzureAttester verifies Azure MAA tokens from the agent endpoint (issuer is
// the pinned MAA instance URL).
func NewAzureAttester(keys map[string]crypto.PublicKey, issuer, baseURL string) Attester {
	return &azureAttester{keys: keys, issuer: issuer, isReady: true, fetch: endpointMAAFetch(baseURL)}
}

// NewAWSAttester verifies raw AWS SEV-SNP reports (go-sev-guest + the VLEK chain
// from AMD KDS) from the agent endpoint.
func NewAWSAttester(baseURL string) Attester {
	return &awsAttester{fetchChain: fetchVLEKChainFromKDS, isReady: true, fetch: endpointSNPFetch(baseURL)}
}

// endpointMAAFetch reads MAA evidence from the agent /attest endpoint.
func endpointMAAFetch(baseURL string) maaFetch {
	return func(ctx context.Context, nonce []byte) (maaEvidence, error) {
		ev, err := csEndpointFetch(baseURL)(ctx, nonce)
		if err != nil {
			return maaEvidence{}, err
		}
		return maaEvidence{token: ev.token, channelKey: ev.channelKey}, nil
	}
}
