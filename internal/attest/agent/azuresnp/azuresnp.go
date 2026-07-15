//go:build linux

// Package azuresnpagent gathers direct Azure SEV-SNP + vTPM evidence. The
// measured image bakes this agent into a dm-verity root and pins PCR11.
package azuresnpagent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	legacytpm "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

const (
	akHandle                  = tpmutil.Handle(0x81000003)
	hclReportIndex            = tpmutil.Handle(0x1400001)
	hclHeaderLength           = 0x20
	snpReportLength           = 0x4a0
	snpRuntimeDataPadding     = 0x14
	azureTHIMCertificationURL = "http://169.254.169.254/metadata/THIM/amd/certification"
	maxTHIMCertificationBytes = 2 << 20
)

// attestFunc gathers the SNP report and HCL runtime data, then asks Azure's
// persistent vTPM AK to quote PCR11 with extraData bound to the run nonce and
// ephemeral channel key. It intentionally avoids parsing the unrelated UEFI
// event log: PCR11 is verified directly, and eliminating that parser removes a
// credential-boundary dependency on GO-2026-5298.
func attestFunc() agent.AttestFunc {
	return func(ctx context.Context, runNonce, channelPub []byte) (string, error) {
		binding := agent.MAABindingNonce(runNonce, channelPub)

		rwc, err := legacytpm.OpenTPM()
		if err != nil {
			return "", fmt.Errorf("open tpm: %w", err)
		}
		defer rwc.Close()

		snpReport, runtimeData, err := readAzureHCLReport(rwc)
		if err != nil {
			return "", fmt.Errorf("gather snp/runtime evidence: %w", err)
		}
		vcekPEM, chainPEM, err := fetchAzureTHIMCertificates(ctx, http.DefaultClient)
		if err != nil {
			return "", fmt.Errorf("fetch vcek chain: %w", err)
		}

		selection := legacytpm.PCRSelection{Hash: legacytpm.AlgSHA256, PCRs: []int{11}}
		quote, sig, err := legacytpm.Quote(rwc, akHandle, "", "", binding, selection, legacytpm.AlgNull)
		if err != nil {
			return "", fmt.Errorf("quote pcr11: %w", err)
		}
		pcrs, err := legacytpm.ReadPCRs(rwc, selection)
		if err != nil {
			return "", fmt.Errorf("read pcr11: %w", err)
		}
		if sig.RSA == nil {
			return "", fmt.Errorf("vTPM AK quote is not RSA-signed")
		}

		vcekDER, err := firstCertDER(vcekPEM)
		if err != nil {
			return "", fmt.Errorf("vcek: %w", err)
		}
		askDER, err := firstCertDER(chainPEM)
		if err != nil {
			return "", fmt.Errorf("ask: %w", err)
		}
		pcrMap := make(map[uint32][]byte, len(pcrs))
		for idx, digest := range pcrs {
			pcrMap[uint32(idx)] = digest
		}

		ev := agent.AzureSNPEvidence{
			SNPReport:   snpReport,
			VCEK:        vcekDER,
			ASK:         askDER,
			RuntimeData: runtimeData,
			Quote:       quote,
			QuoteSig:    sig.RSA.Signature,
			PCRs:        pcrMap,
			ChannelKey:  channelPub,
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(raw), nil
	}
}

func readAzureHCLReport(rwc io.ReadWriter) ([]byte, []byte, error) {
	raw, err := legacytpm.NVReadEx(rwc, hclReportIndex, legacytpm.HandleOwner, "", 0)
	if err != nil {
		return nil, nil, err
	}
	minimum := hclHeaderLength + snpReportLength + snpRuntimeDataPadding
	if len(raw) <= minimum {
		return nil, nil, fmt.Errorf("HCL report is shorter than expected: %d bytes", len(raw))
	}
	body := raw[hclHeaderLength:]
	runtimeData, _, _ := bytes.Cut(body[snpReportLength+snpRuntimeDataPadding:], []byte{0})
	return body[:snpReportLength], runtimeData, nil
}

func fetchAzureTHIMCertificates(ctx context.Context, client *http.Client) ([]byte, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, azureTHIMCertificationURL, http.NoBody)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Metadata", "True")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("THIM returned %s", resp.Status)
	}
	var result struct {
		VcekCert         string `json:"vcekCert"`
		CertificateChain string `json:"certificateChain"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxTHIMCertificationBytes))
	if err := dec.Decode(&result); err != nil {
		return nil, nil, err
	}
	if result.VcekCert == "" || result.CertificateChain == "" {
		return nil, nil, fmt.Errorf("THIM response is missing VCEK certificate data")
	}
	return []byte(result.VcekCert), []byte(result.CertificateChain), nil
}

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

// RunAgent serves the sealed-exchange API on addr.
func RunAgent(addr string) error {
	return agent.RunServer(addr, attestFunc())
}
