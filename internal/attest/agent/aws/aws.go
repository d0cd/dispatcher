// Package awsagent is the in-TEE agent for AWS SEV-SNP confidential runs: the
// shared sealed-exchange agent, attesting via a raw SEV-SNP report from
// /dev/sev-guest. It is compiled into the dispatcher-attest-aws binary, so only
// that binary pulls in the SEV-SNP report library.
package awsagent

import (
	"context"
	"encoding/base64"

	"github.com/google/go-sev-guest/client"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// attestFunc binds SHA-512(runNonce ‖ channelPub) into a raw SEV-SNP report via
// /dev/sev-guest (REPORT_DATA is guest-settable on AWS, unlike Azure's boot-fixed
// vTPM). It returns the base64 report+cert-table (as from GetRawQuote); dispatcher
// decodes and verifies it with go-sev-guest. The 64-byte SHA-512 fills REPORT_DATA.
func attestFunc() agent.AttestFunc {
	return func(_ context.Context, runNonce, channelPub []byte) (string, error) {
		var reportData [64]byte
		copy(reportData[:], agent.BindingHash(runNonce, channelPub))
		qp, err := client.GetQuoteProvider()
		if err != nil {
			return "", err
		}
		raw, err := qp.GetRawQuote(reportData)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(raw), nil
	}
}

// RunAgent starts the in-TEE agent on an AWS SEV-SNP VM, attesting via a raw
// SEV-SNP report instead of a vendor token.
func RunAgent(addr string) error {
	return agent.RunServer(addr, attestFunc())
}
