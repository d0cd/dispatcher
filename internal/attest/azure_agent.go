package attest

import (
	"context"
	"net/http"

	"github.com/edgelesssys/go-azguestattestation/maa"
)

// azureMAAAttestFunc binds SHA-256(runNonce ‖ channelPub) into an Azure MAA token
// via the vTPM. It reuses the maintained, pure-Go edgelesssys guest-attestation
// library (vTPM read → HCL parse → MAA REST); the 32-byte binding fits the TPM
// quote's qualifying data. MAA echoes it in x-ms-runtime.client-payload.nonce.
func azureMAAAttestFunc(maaURL string) attestFunc {
	return func(ctx context.Context, runNonce, channelPub []byte) (string, error) {
		return maa.Attest(ctx, maaBindingNonce(runNonce, channelPub), maaURL, http.DefaultClient)
	}
}

// RunAzureAgent starts the in-TEE agent on an Azure confidential VM: the same
// HTTP sealed-exchange agent as GCP, but attesting via MAA instead of the CS
// teeserver. dispatcher scps this binary to the booted CVM and starts it.
func RunAzureAgent(addr, maaURL string) error {
	agent, err := newConfidentialAgent(agentConfig{
		attest: azureMAAAttestFunc(maaURL),
		runner: defaultRunner,
	})
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: agent.handler()}
	return srv.ListenAndServe()
}
