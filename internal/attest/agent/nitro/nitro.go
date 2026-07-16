//go:build linux

// Package nitroagent is the in-enclave agent for AWS Nitro Enclaves confidential
// runs: the shared sealed-exchange agent served over vsock (a Nitro enclave has no
// network stack), attesting via the Nitro Security Module (/dev/nsm). It is
// compiled into the dispatcher-attest-nitro binary that ships inside the measured
// enclave image, so only that binary links the vsock and NSM libraries.
package nitroagent

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/mdlayher/vsock"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// attestFunc obtains a Nitro attestation document from /dev/nsm binding this run's
// nonce and the agent's channel public key into the document's nonce/public_key
// fields (the Nitro hypervisor signs the whole document, so both are attested). It
// returns base64(COSE_Sign1 doc); dispatcher decodes and verifies it against the
// pinned AWS Nitro root.
func attestFunc() agent.AttestFunc {
	return func(_ context.Context, runNonce, channelPub []byte) (string, error) {
		sess, err := nsm.OpenDefaultSession()
		if err != nil {
			return "", fmt.Errorf("open nsm session: %w", err)
		}
		defer sess.Close()

		res, err := sess.Send(&request.Attestation{Nonce: runNonce, PublicKey: channelPub})
		if err != nil {
			return "", fmt.Errorf("nsm attestation: %w", err)
		}
		if res.Attestation == nil || len(res.Attestation.Document) == 0 {
			return "", fmt.Errorf("nsm returned no attestation document")
		}
		return base64.StdEncoding.EncodeToString(res.Attestation.Document), nil
	}
}

// RunAgent listens on the given vsock port inside the enclave and serves the
// sealed-exchange API, attesting via the Nitro Security Module. The parent
// instance proxies dispatcher's TCP connection to this vsock port.
func RunAgent(port uint32) error {
	l, err := vsock.Listen(port, nil)
	if err != nil {
		return fmt.Errorf("listen vsock:%d: %w", port, err)
	}
	return agent.ServeATLSOn(l, attestFunc())
}
