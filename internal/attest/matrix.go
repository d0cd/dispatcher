package attest

import (
	"fmt"
	"strings"
)

// This file is the single source of truth for WHAT each confidential-compute
// backend actually verifies. The security docs (docs/confidential-computing.md,
// SECURITY.md) make per-guarantee claims that used to drift from the code because
// they were hand-maintained prose; the enforcement matrix below is derived from
// the verifiers in this package, and TestMatrix_DocInSync locks the rendered
// table into the doc so a code change that isn't reflected in the docs fails CI.
//
// Every cell here must match the corresponding verifier: csAttester
// (confidential_space.go), azureAttester (maa.go), azureSNPAttester
// (azure_snp.go), awsAttester (aws_snp.go), nitroAttester (nitro.go), and the
// shared applyPolicy (attestation_policy.go). TestMatrix_GroundedInCode ties the
// security-critical cells to the actual verifier behavior.

// Enforcement is how strongly a backend applies a security control at attestation
// time.
type Enforcement string

const (
	// Enforced: the verifier checks the control and rejects the run on failure.
	Enforced Enforcement = "enforced"
	// FailClosed: the backend cannot verify the control, so a run that REQUESTS it
	// is rejected outright rather than silently accepted.
	FailClosed Enforcement = "fail-closed"
	// NotEnforced: the control is applicable to this TEE but the verifier does not
	// check it — a known gap.
	NotEnforced Enforcement = "not-enforced"
	// NotApplicable: the control has no meaning for this TEE technology.
	NotApplicable Enforcement = "n/a"
)

// Control is one security property a confidential run can demand of its TEE.
type Control string

const (
	ControlGenuineTEE     Control = "Genuine TEE (signature + chain to pinned root)"
	ControlMeasurement    Control = "Measurement/identity on exact allowlist (empty fails closed)"
	ControlNonce          Control = "Per-run nonce freshness"
	ControlChannelBinding Control = "Channel-key binding (sealed only to the attested key)"
	ControlDebugOff       Control = "Debug disabled"
	ControlMigrationOff   Control = "Migration disabled"
	ControlMinTCB         Control = "Minimum TCB / firmware floor"
	ControlRevocation     Control = "Certificate revocation"
	ControlMeasuredAgent  Control = "Attestation agent folded into the measured boot"
)

// controlOrder fixes the row order of the rendered matrix (deterministic output).
var controlOrder = []Control{
	ControlGenuineTEE,
	ControlMeasurement,
	ControlNonce,
	ControlChannelBinding,
	ControlDebugOff,
	ControlMigrationOff,
	ControlMinTCB,
	ControlRevocation,
	ControlMeasuredAgent,
}

// Backend is one confidential-compute attestation path.
type Backend struct {
	ID       string // stable id; matches the profile/provider routing in the CLI
	Short    string // column header
	Anchor   string // the root of trust the chain terminates at
	Controls map[Control]Enforcement
	Notes    map[Control]string // optional per-cell caveat, rendered as a footnote
}

// ConfidentialMatrix states, per backend, which controls the verifier enforces.
// Keep it in lockstep with the verifiers — TestMatrix_Complete /
// TestMatrix_GroundedInCode / TestMatrix_DocInSync guard it.
var ConfidentialMatrix = []Backend{
	{
		ID: "gcp-confidential-space", Short: "GCP CS", Anchor: "Google JWKS",
		Controls: map[Control]Enforcement{
			ControlGenuineTEE:     Enforced,
			ControlMeasurement:    Enforced,
			ControlNonce:          Enforced,
			ControlChannelBinding: Enforced,
			ControlDebugOff:       Enforced,
			ControlMigrationOff:   NotApplicable,
			ControlMinTCB:         FailClosed,
			ControlRevocation:     NotApplicable,
			ControlMeasuredAgent:  Enforced,
		},
		Notes: map[Control]string{
			ControlMeasurement:   "the attested identity is the container image digest",
			ControlMigrationOff:  "the Confidential Space token exposes no migration claim",
			ControlMinTCB:        "the CS token carries no reported TCB, so a run that sets minTCB is rejected (GCP has no measured-TCB backend)",
			ControlRevocation:    "delegated to the Google Confidential Space service; dispatcher validates no AMD cert chain locally",
			ControlMeasuredAgent: "the measured container image is the workload",
		},
	},
	{
		ID: "azure-maa", Short: "Azure MAA", Anchor: "pinned MAA issuer + JWKS",
		Controls: map[Control]Enforcement{
			ControlGenuineTEE:     Enforced,
			ControlMeasurement:    Enforced,
			ControlNonce:          Enforced,
			ControlChannelBinding: Enforced,
			ControlDebugOff:       Enforced,
			ControlMigrationOff:   Enforced,
			ControlMinTCB:         FailClosed,
			ControlRevocation:     NotApplicable,
			ControlMeasuredAgent:  NotEnforced,
		},
		Notes: map[Control]string{
			ControlMigrationOff:  "verified via the x-ms-sevsnpvm-migration-allowed token claim",
			ControlMinTCB:        "no reported TCB in the token, so a run that sets minTCB is rejected — use profile: azure-snp",
			ControlRevocation:    "delegated to the Azure MAA service; dispatcher validates no AMD cert chain locally",
			ControlMeasuredAgent: "the standard path scp's the agent; measured only when a custom measured image + PCR pins are configured",
		},
	},
	{
		ID: "azure-snp", Short: "Azure SNP", Anchor: "pinned AMD ARK",
		Controls: map[Control]Enforcement{
			ControlGenuineTEE:     Enforced,
			ControlMeasurement:    Enforced,
			ControlNonce:          Enforced,
			ControlChannelBinding: Enforced,
			ControlDebugOff:       Enforced,
			ControlMigrationOff:   Enforced,
			ControlMinTCB:         Enforced,
			ControlRevocation:     Enforced,
			ControlMeasuredAgent:  Enforced,
		},
		Notes: map[Control]string{
			ControlMeasurement:   "PCR11 (the UKI carrying the agent), pinned",
			ControlRevocation:    "the ARK-signed CRL at the ASK's AMD KDS distribution point; a revoked VCEK/ASK is rejected, fail-closed if the CRL is missing or unreachable",
			ControlMeasuredAgent: "PCR11 = the UKI carrying the agent",
		},
	},
	{
		ID: "aws-sev-snp", Short: "AWS SNP", Anchor: "pinned AMD ARK (go-sev-guest)",
		Controls: map[Control]Enforcement{
			ControlGenuineTEE:     Enforced,
			ControlMeasurement:    Enforced,
			ControlNonce:          Enforced,
			ControlChannelBinding: Enforced,
			ControlDebugOff:       Enforced,
			ControlMigrationOff:   Enforced,
			ControlMinTCB:         Enforced,
			ControlRevocation:     Enforced,
			ControlMeasuredAgent:  NotEnforced,
		},
		Notes: map[Control]string{
			ControlRevocation:    "ASVK CRL checked against the pinned ARK (via go-sev-guest)",
			ControlMeasuredAgent: "the standard path scp's the agent; it is not folded into the launch measurement (use profile: nitro)",
		},
	},
	{
		ID: "aws-nitro", Short: "AWS Nitro", Anchor: "pinned AWS Nitro root",
		Controls: map[Control]Enforcement{
			ControlGenuineTEE:     Enforced,
			ControlMeasurement:    Enforced,
			ControlNonce:          Enforced,
			ControlChannelBinding: Enforced,
			ControlDebugOff:       NotApplicable,
			ControlMigrationOff:   NotApplicable,
			ControlMinTCB:         NotApplicable,
			ControlRevocation:     NotApplicable,
			ControlMeasuredAgent:  Enforced,
		},
		Notes: map[Control]string{
			ControlMeasurement:   "PCR0 (the enclave image), pinned",
			ControlDebugOff:      "Nitro enclaves have no SEV-SNP debug/migration policy bits",
			ControlRevocation:    "AWS uses ephemeral certs (leaf valid ~3h) instead of CRLs and instructs validators to disable CRL checking; short validity is the revocation mechanism, enforced by chain-validity checking",
			ControlMeasuredAgent: "PCR0 = the enclave image carrying the agent",
		},
	},
}

// cell renders one enforcement value as a table symbol.
func (e Enforcement) cell() string {
	switch e {
	case Enforced:
		return "✓"
	case NotEnforced:
		return "✗"
	case FailClosed:
		return "fail-closed"
	case NotApplicable:
		return "n/a"
	default:
		return string(e)
	}
}

// RenderMarkdown renders the enforcement matrix as a deterministic markdown table
// plus a footnote list. docs/confidential-computing.md embeds this verbatim; the
// lock is TestMatrix_DocInSync.
func RenderMarkdown() string {
	var b strings.Builder

	header := "| Control |"
	sep := "|---|"
	for _, be := range ConfidentialMatrix {
		header += " " + be.Short + " |"
		sep += "---|"
	}
	b.WriteString(header + "\n")
	b.WriteString(sep + "\n")

	for _, ctrl := range controlOrder {
		row := "| " + string(ctrl) + " |"
		for _, be := range ConfidentialMatrix {
			row += " " + be.Controls[ctrl].cell() + " |"
		}
		b.WriteString(row + "\n")
	}

	// Roots of trust, then per-cell footnotes, both in deterministic order.
	b.WriteString("\n**Roots of trust:** ")
	anchors := make([]string, 0, len(ConfidentialMatrix))
	for _, be := range ConfidentialMatrix {
		anchors = append(anchors, fmt.Sprintf("%s = %s", be.Short, be.Anchor))
	}
	b.WriteString(strings.Join(anchors, "; ") + ".\n")

	var notes []string
	for _, be := range ConfidentialMatrix {
		for _, ctrl := range controlOrder {
			if n := be.Notes[ctrl]; n != "" {
				notes = append(notes, fmt.Sprintf("- **%s — %s:** %s", be.Short, string(ctrl), n))
			}
		}
	}
	if len(notes) > 0 {
		b.WriteString("\n" + strings.Join(notes, "\n") + "\n")
	}
	return b.String()
}
