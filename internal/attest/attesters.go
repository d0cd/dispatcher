package attest

import (
	"context"
	"crypto"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// The attester constructors expose the provider verifiers over the in-TEE agent's
// /attest endpoint, keeping the fetch/evidence types internal to this package.
// dispatcher (the cloud adapters) just calls the right constructor + Verify.

// NewCSAttester verifies GCP Confidential Space tokens from the agent endpoint.
func NewCSAttester(keys map[string]crypto.PublicKey, baseURL string) Attester {
	return &csAttester{keys: keys, fetch: csEndpointFetch(baseURL)}
}

// NewAzureAttester verifies Azure MAA tokens from the agent endpoint (issuer is
// the pinned MAA instance URL). mb optionally pins measured-boot PCRs; its zero
// value keeps the firmware-only behavior (no measured-agent enforcement).
func NewAzureAttester(keys map[string]crypto.PublicKey, issuer, baseURL string, mb MAAMeasuredBoot) Attester {
	return &azureAttester{keys: keys, issuer: issuer, mb: mb, fetch: endpointMAAFetch(baseURL)}
}

// NewAWSAttester verifies raw AWS SEV-SNP reports (go-sev-guest + the VLEK chain
// from AMD KDS) from the agent endpoint.
func NewAWSAttester(baseURL string) Attester {
	return &awsAttester{fetchChain: fetchVLEKChainFromKDS, fetch: endpointSNPFetch(baseURL)}
}

// endpointMAAFetch reads MAA evidence (the signed token) from the agent's
// /attest endpoint over the untrusted channel, binding the run nonce.
func endpointMAAFetch(baseURL string) maaFetch {
	return func(ctx context.Context, nonce []byte) (maaEvidence, error) {
		token, channelKey, err := agent.FetchAttestation(ctx, baseURL, nonce)
		if err != nil {
			return maaEvidence{}, err
		}
		return maaEvidence{token: token, channelKey: channelKey}, nil
	}
}
