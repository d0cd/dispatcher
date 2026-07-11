package cloudvm

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/google/go-sev-guest/client"
)

// awsSNPAttestFunc binds SHA-512(runNonce ‖ channelPub) into a raw SEV-SNP report
// via /dev/sev-guest (REPORT_DATA is settable on AWS, unlike Azure's boot-fixed
// vTPM). It returns the base64 report+cert-table (as from GetRawQuote); dispatcher
// decodes and verifies it with go-sev-guest. The 64-byte SHA-512 fills REPORT_DATA.
func awsSNPAttestFunc() attestFunc {
	return func(_ context.Context, runNonce, channelPub []byte) (string, error) {
		var reportData [64]byte
		copy(reportData[:], bindingHash(runNonce, channelPub))
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

// RunAWSAgent starts the in-TEE agent on an AWS SEV-SNP VM — the same HTTP sealed-
// exchange agent, attesting via a raw SEV-SNP report instead of a vendor token.
func RunAWSAgent(addr string) error {
	agent, err := newConfidentialAgent(agentConfig{attest: awsSNPAttestFunc(), runner: defaultRunner})
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: agent.handler()}
	return srv.ListenAndServe()
}

// endpointSNPFetch is an snpFetch that reads SEV-SNP evidence from the in-TEE
// agent's /attest endpoint (base64 report) over the same untrusted channel GCP/
// Azure use.
func endpointSNPFetch(baseURL string) snpFetch {
	return func(ctx context.Context, vm *VMInfo, sshKeyPath, sshUser string, nonce []byte) (snpEvidence, error) {
		ev, err := csEndpointFetch(baseURL)(ctx, vm, sshKeyPath, sshUser, nonce)
		if err != nil {
			return snpEvidence{}, err
		}
		report, err := base64.StdEncoding.DecodeString(ev.token)
		if err != nil {
			return snpEvidence{}, err
		}
		return snpEvidence{report: report, channelKey: ev.channelKey}, nil
	}
}
