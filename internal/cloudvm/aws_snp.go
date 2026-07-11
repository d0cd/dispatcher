package cloudvm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"

	"github.com/d0cd/dispatcher/internal/types"
)

// AWS confidential VMs are raw SEV-SNP (there is no vendor MAA/CS token). The
// hardware report is verified with google/go-sev-guest — the vetted SEV-SNP
// library — not hand-rolled code: it checks the firmware signature and the AMD
// certificate chain. AWS signs with VLEK (not VCEK), and its cert table carries
// only the VLEK leaf, so the ASVK intermediate + ARK root must be supplied from
// AMD KDS (the VLEK cert chain). The nonce/channel-key binding then rides in
// REPORT_DATA (settable via /dev/sev-guest), verified by applyPolicy — the same
// SHA-512(nonce ‖ channelKey) binding the raw path was built for.

// awsVLEKChainFetcher returns the PEM VLEK cert chain (ASVK + ARK) for a product
// line. Production fetches from AMD KDS; tests inject a captured chain.
type awsVLEKChainFetcher func(productLine string) ([]byte, error)

// fetchVLEKChainFromKDS retrieves the VLEK cert chain from AMD's Key Distribution
// Service for the given product line (e.g. "Milan", "Genoa").
func fetchVLEKChainFromKDS(productLine string) ([]byte, error) {
	url := fmt.Sprintf("https://kdsintf.amd.com/vlek/v1/%s/cert_chain", productLine)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch VLEK chain: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AMD KDS VLEK chain %s: %d", productLine, resp.StatusCode)
	}
	return body, nil
}

// verifyAWSSNPReport verifies a raw SEV-SNP report (report + cert table, as from
// GetRawQuote) using go-sev-guest with the VLEK chain from fetchChain, and
// projects it onto provider-agnostic Claims. The caller runs applyPolicy for the
// measurement allowlist + REPORT_DATA binding.
func verifyAWSSNPReport(raw []byte, fetchChain awsVLEKChainFetcher) (Claims, error) {
	att, err := abi.ReportCertsToProto(raw)
	if err != nil {
		return Claims{}, fmt.Errorf("parse snp report: %w", err)
	}
	r := att.Report

	product := abi.SevProductFromCpuid1Eax(r.GetCpuid1EaxFms())
	productLine := kds.ProductLine(product)
	chainPEM, err := fetchChain(productLine)
	if err != nil {
		return Claims{}, fmt.Errorf("obtain VLEK chain for %s: %w", productLine, err)
	}
	pc := &trust.ProductCerts{}
	if err := pc.FromKDSCertBytes(chainPEM); err != nil {
		return Claims{}, fmt.Errorf("parse VLEK chain: %w", err)
	}

	opts := verify.DefaultOptions()
	opts.Product = product
	opts.TrustedRoots = map[string][]*trust.AMDRootCerts{
		productLine: {{ProductLine: productLine, ProductCerts: pc}},
	}
	if err := verify.SnpAttestation(att, opts); err != nil {
		return Claims{}, fmt.Errorf("aws snp verification: %w", err)
	}

	return Claims{
		TEEType:          "sev-snp",
		Measurement:      hex.EncodeToString(r.GetMeasurement()),
		DebugEnabled:     r.GetPolicy()&snpPolicyDebug != 0,
		MigrationEnabled: r.GetPolicy()&snpPolicyMigrateMA != 0,
		TCB:              r.GetReportedTcb(),
		ReportData:       r.GetReportData(),
	}, nil
}

// awsAttester verifies AWS SEV-SNP VMs via a raw report (go-sev-guest + the VLEK
// chain) and the REPORT_DATA binding. isReady is false until a fetch is wired.
type awsAttester struct {
	fetchChain awsVLEKChainFetcher
	fetch      snpFetch
	isReady    bool
}

func (a *awsAttester) ready() bool { return a.isReady }

func (a *awsAttester) Verify(ctx context.Context, vm *VMInfo, sshKeyPath, sshUser string, req types.ConfidentialRequirement) (AttestationResult, error) {
	if a.fetch == nil {
		return AttestationResult{}, fmt.Errorf("aws attester has no evidence fetch wired")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return AttestationResult{}, fmt.Errorf("generate attestation nonce: %w", err)
	}

	ev, err := a.fetch(ctx, vm, sshKeyPath, sshUser, nonce)
	if err != nil {
		return AttestationResult{}, fmt.Errorf("fetch snp evidence: %w", err)
	}
	claims, err := verifyAWSSNPReport(ev.report, a.fetchChain)
	if err != nil {
		return AttestationResult{}, err
	}
	policy := VerificationPolicy{
		ExpectedType: req.Type,
		Measurements: req.Measurements,
		MinTCB:       req.MinTCB,
		Nonce:        nonce,
		ChannelKey:   ev.channelKey,
	}
	if err := applyPolicy(claims, policy); err != nil {
		return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: err.Error()}, nil
	}
	return AttestationResult{
		Verified:    true,
		Type:        claims.TEEType,
		Measurement: claims.Measurement,
		TCB:         claims.TCB,
		Nonce:       hex.EncodeToString(nonce),
		Verdict:     "verified",
		ChannelKey:  ev.channelKey,
	}, nil
}
