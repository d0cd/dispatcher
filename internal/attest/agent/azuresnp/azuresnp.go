//go:build linux

// Package azuresnpagent is the in-CVM agent for Azure confidential VMs using
// direct SEV-SNP + vTPM attestation (Constellation-style, no MAA). It gathers the
// SNP report + HCL runtime data + an AK-signed TPM quote over PCR11 (the UKI
// carrying the agent) and serves the sealed exchange over TCP. Only this binary
// links the vTPM/SNP evidence libraries (go-azguestattestation, go-tpm-tools).
package azuresnpagent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/edgelesssys/go-azguestattestation/maa"
	"github.com/google/go-tpm-tools/client"
	legacytpm "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// akHandle is the persistent handle where Azure provisions the vTPM Attestation
// Key on a confidential VM.
const akHandle = tpmutil.Handle(0x81000003)

// attestFunc gathers the direct-verification evidence for this run: the SNP report
// + HCL runtime data (which binds the AK) via go-azguestattestation, and a vTPM
// quote over PCR11 signed by the AK with extraData = the run+channel binding.
func attestFunc() agent.AttestFunc {
	return func(ctx context.Context, runNonce, channelPub []byte) (string, error) {
		binding := agent.MAABindingNonce(runNonce, channelPub)

		rwc, err := legacytpm.OpenTPM()
		if err != nil {
			return "", fmt.Errorf("open tpm: %w", err)
		}
		defer rwc.Close()

		// SNP report + HCL runtime data + VCEK chain (fetched from AMD KDS).
		params, err := maa.NewParameters(ctx, binding, http.DefaultClient, rwc)
		if err != nil {
			return "", fmt.Errorf("gather snp/runtime evidence: %w", err)
		}

		// A vTPM quote over PCR11, signed by the Azure AK, bound to this run.
		ak, err := client.LoadCachedKey(rwc, akHandle, client.NullSession{})
		if err != nil {
			return "", fmt.Errorf("load vTPM AK: %w", err)
		}
		defer ak.Close()
		quote, err := ak.Quote(legacytpm.PCRSelection{Hash: legacytpm.AlgSHA256, PCRs: []int{11}}, binding)
		if err != nil {
			return "", fmt.Errorf("quote pcr11: %w", err)
		}
		sig, err := legacytpm.DecodeSignature(bytes.NewBuffer(quote.GetRawSig()))
		if err != nil {
			return "", fmt.Errorf("decode quote signature: %w", err)
		}
		if sig.RSA == nil {
			return "", fmt.Errorf("vTPM AK quote is not RSA-signed")
		}

		vcekDER, err := firstCertDER(params.VcekCert)
		if err != nil {
			return "", fmt.Errorf("vcek: %w", err)
		}
		askDER, err := firstCertDER(params.VcekChain)
		if err != nil {
			return "", fmt.Errorf("ask: %w", err)
		}

		ev := agent.AzureSNPEvidence{
			SNPReport:   params.SNPReport,
			VCEK:        vcekDER,
			ASK:         askDER,
			RuntimeData: params.RuntimeData,
			Quote:       quote.GetQuote(),
			QuoteSig:    sig.RSA.Signature,
			PCRs:        quote.GetPcrs().GetPcrs(),
			ChannelKey:  channelPub,
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(raw), nil
	}
}

// firstCertDER returns the DER of the first PEM certificate block in b (the VCEK
// leaf, or the ASK at the head of the KDS cert chain).
func firstCertDER(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, err
	}
	return block.Bytes, nil
}

// RunAgent serves the sealed-exchange API on addr, attesting via direct SNP+vTPM
// evidence. The measured CVM image bakes this binary into the UKI.
func RunAgent(addr string) error {
	return agent.RunServer(addr, attestFunc())
}
