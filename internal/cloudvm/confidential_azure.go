package cloudvm

import "context"

// endpointMAAFetch is a maaFetch that reads MAA evidence from the in-TEE agent's
// /attest endpoint — the same untrusted-channel transport GCP Confidential Space
// uses (csEndpointFetch), except the returned token is an Azure MAA token. Wired
// into azureAttester once the CVM's agent is reachable.
func endpointMAAFetch(baseURL string) maaFetch {
	return func(ctx context.Context, vm *VMInfo, sshKeyPath, sshUser string, nonce []byte) (maaEvidence, error) {
		ev, err := csEndpointFetch(baseURL)(ctx, vm, sshKeyPath, sshUser, nonce)
		if err != nil {
			return maaEvidence{}, err
		}
		return maaEvidence{token: ev.token, channelKey: ev.channelKey}, nil
	}
}
