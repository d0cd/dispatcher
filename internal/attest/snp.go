package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// AMD SEV-SNP ATTESTATION_REPORT ABI offsets (Table 22, "SEV Secure Nested
// Paging Firmware ABI Specification"). Only the fields the verifier needs are
// named. The report is 0x4A0 bytes; the firmware's ECDSA signature covers the
// first 0x2A0 bytes.
const (
	snpReportLen    = 0x4A0
	snpSignedLen    = 0x2A0
	snpOffPolicy    = 0x08
	snpOffSigAlgo   = 0x34
	snpOffData      = 0x50  // REPORT_DATA, 64 bytes
	snpOffMeas      = 0x90  // MEASUREMENT, 48 bytes
	snpOffTCB       = 0x180 // REPORTED_TCB, u64
	snpLenData      = 64
	snpLenMeas      = 48
	snpSigComponent = 72 // r and s are each stored little-endian in 72 bytes

	snpSigAlgoECDSAP384SHA384 = 1
	snpPolicyDebug            = uint64(1) << 19 // DEBUG: debugging permitted
	snpPolicyMigrateMA        = uint64(1) << 18 // MIGRATE_MA: migration agent permitted
)

func leUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func leUint64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

// leToBigInt reads a little-endian fixed-width field (AMD's r/s layout) as a
// big.Int by reversing it to big-endian.
func leToBigInt(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return new(big.Int).SetBytes(be)
}

// snpReport holds the parsed fields the policy engine acts on, plus the raw
// bytes needed to re-check the firmware signature.
type snpReport struct {
	signed      []byte // the 0x2A0-byte signed prefix
	sigAlgo     uint32
	policy      uint64
	reportedTCB uint64
	measurement []byte
	reportData  []byte
	sigR, sigS  *big.Int
}

// parseSNPReport decodes an AMD SEV-SNP attestation report. It validates only
// the structural length here; signature and policy are checked separately.
func parseSNPReport(b []byte) (*snpReport, error) {
	if len(b) < snpReportLen {
		return nil, fmt.Errorf("snp report too short: got %d bytes, need %d", len(b), snpReportLen)
	}
	return &snpReport{
		signed:      append([]byte(nil), b[:snpSignedLen]...),
		sigAlgo:     leUint32(b[snpOffSigAlgo:]),
		policy:      leUint64(b[snpOffPolicy:]),
		reportedTCB: leUint64(b[snpOffTCB:]),
		measurement: append([]byte(nil), b[snpOffMeas:snpOffMeas+snpLenMeas]...),
		reportData:  append([]byte(nil), b[snpOffData:snpOffData+snpLenData]...),
		sigR:        leToBigInt(b[snpSignedLen : snpSignedLen+snpSigComponent]),
		sigS:        leToBigInt(b[snpSignedLen+snpSigComponent : snpSignedLen+2*snpSigComponent]),
	}, nil
}

// claims projects the report onto the provider-agnostic Claims the policy
// engine consumes. SEV-SNP has no separate "sev" mode in a SNP report.
func (r *snpReport) claims() Claims {
	return Claims{
		TEEType:          "sev-snp",
		Measurement:      hex.EncodeToString(r.measurement),
		DebugEnabled:     r.policy&snpPolicyDebug != 0,
		MigrationEnabled: r.policy&snpPolicyMigrateMA != 0,
		TCB:              r.reportedTCB,
		ReportData:       r.reportData,
	}
}

// verifySNPSignature checks the firmware's ECDSA-P384/SHA-384 signature over the
// signed prefix using the VCEK public key, binding the report to the hardware root.
func verifySNPSignature(r *snpReport, vcek *x509.Certificate) error {
	if r.sigAlgo != snpSigAlgoECDSAP384SHA384 {
		return fmt.Errorf("snp report uses unsupported signature algorithm %d", r.sigAlgo)
	}
	pub, ok := vcek.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return fmt.Errorf("snp VCEK is not an ECDSA P-384 key")
	}
	digest := sha512.Sum384(r.signed)
	if !ecdsa.Verify(pub, digest[:], r.sigR, r.sigS) {
		return fmt.Errorf("snp report signature does not verify against the VCEK")
	}
	return nil
}

// verifySNPChain checks VCEK <- ASK and that the ASK chains to one of the pinned
// AMD ARK roots (R4). Trying each root avoids mapping the report's product line
// (Milan/Genoa/Turin) to a specific ARK up front. It validates only the
// signature links: time validity and revocation are the live-fetch layer's
// concern.
func verifySNPChain(vcek, ask *x509.Certificate, roots []*x509.Certificate) error {
	if vcek == nil || ask == nil {
		return fmt.Errorf("snp cert chain incomplete")
	}
	if len(roots) == 0 {
		return fmt.Errorf("snp: no pinned AMD roots configured")
	}
	if err := vcek.CheckSignatureFrom(ask); err != nil {
		return fmt.Errorf("snp VCEK is not signed by the ASK: %w", err)
	}
	for _, ark := range roots {
		if ask.CheckSignatureFrom(ark) == nil {
			return nil
		}
	}
	return fmt.Errorf("snp ASK chains to none of the %d pinned AMD roots", len(roots))
}

// snpEvidence is what the per-VM fetch returns: the raw report and the in-TEE
// channel public key the report binds. The ARK is pinned on the attester, not
// fetched from the guest.
type snpEvidence struct {
	report     []byte
	channelKey []byte
}

// snpFetch obtains attestation evidence from a booted confidential VM, binding
// the verifier's per-run nonce. It needs a live guest agent (the measured
// image), so it is the one part that cannot be unit-tested offline.
type snpFetch func(ctx context.Context, nonce []byte) (snpEvidence, error)

// endpointSNPFetch reads SEV-SNP evidence (a base64 report+cert-table) from the
// in-TEE agent's /attest endpoint over the untrusted channel, binding the run
// nonce. The AMD cert chain is supplied by the attester (pinned/KDS), not the guest.
func endpointSNPFetch(baseURL string) snpFetch {
	return func(ctx context.Context, nonce []byte) (snpEvidence, error) {
		token, channelKey, err := agent.FetchAttestation(ctx, baseURL, nonce)
		if err != nil {
			return snpEvidence{}, err
		}
		report, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			return snpEvidence{}, err
		}
		return snpEvidence{report: report, channelKey: channelKey}, nil
	}
}
