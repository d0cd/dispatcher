// Package azureagent is the in-TEE agent for Azure confidential (SEV-SNP CVM)
// runs: the shared sealed-exchange agent, attesting via Azure MAA over the vTPM.
// It is compiled into the dispatcher-attest-azure binary, so only that binary
// pulls in the Azure guest-attestation library.
package azureagent

import (
	"context"
	"net/http"

	"github.com/edgelesssys/go-azguestattestation/maa"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// attestFunc binds SHA-256(runNonce ‖ channelPub) into an Azure MAA token via the
// vTPM, using the maintained pure-Go edgelesssys guest-attestation library (vTPM
// read → HCL parse → MAA REST). MAA echoes the binding in
// x-ms-runtime.client-payload.nonce.
func attestFunc(maaURL string) agent.AttestFunc {
	return func(ctx context.Context, runNonce, channelPub []byte) (string, error) {
		return maa.Attest(ctx, agent.MAABindingNonce(runNonce, channelPub), maaURL, http.DefaultClient)
	}
}

// RunAgent starts the in-TEE agent on an Azure confidential VM, attesting via MAA
// instead of the GCP teeserver. dispatcher scps this binary to the booted CVM and
// starts it.
func RunAgent(addr, maaURL string) error {
	return agent.RunServer(addr, attestFunc(maaURL))
}
