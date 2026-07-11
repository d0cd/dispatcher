package attest

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/d0cd/dispatcher/internal/attest/agent"
)

// Claims is the normalized, provider-agnostic set of facts a verifier extracts
// from a TEE's attestation evidence (after it has already checked the
// signature/cert chain to the hardware root — R3/R4). applyPolicy then enforces
// the run's requirements (R5–R8 + freshness/binding) on these claims.
type Claims struct {
	TEEType          string // "sev" | "sev-snp" | "tdx"
	Measurement      string // hex launch measurement
	DebugEnabled     bool   // policy bit: debugging allowed
	MigrationEnabled bool   // policy bit: live migration allowed
	TCB              uint64 // reported TCB/firmware version (higher = newer)
	ReportData       []byte // the report's REPORT_DATA / runtime-data binding
}

// VerificationPolicy is what a confidential run demands of the evidence.
type VerificationPolicy struct {
	ExpectedType string   // requested TEE type; "" or "any" accepts any
	Measurements []string // EXACT allowlist of acceptable launch measurements (hex)
	MinTCB       uint64   // minimum acceptable reported TCB
	Nonce        []byte   // per-run challenge (freshness)
	ChannelKey   []byte   // the in-TEE channel public key bound in REPORT_DATA
}

// applyPolicy enforces R5–R8 and freshness/binding (R1/R2) on extracted claims.
// The caller must already have verified the signature chain (R3/R4). Returns nil
// only when every check passes; any failure must abort and destroy the VM.
func applyPolicy(c Claims, p VerificationPolicy) error {
	// Self-defend on the binding inputs (R1/R2): never trust the caller to have
	// populated them. An empty nonce/key would make the binding check below
	// degenerate to matching agent.BindingHash("","") = SHA-512(""), a public constant
	// any host could place in REPORT_DATA with no genuine TEE or fresh challenge.
	if len(p.Nonce) != 32 {
		return fmt.Errorf("attestation: per-run nonce must be exactly 32 bytes, got %d — R1", len(p.Nonce))
	}
	if len(p.ChannelKey) == 0 {
		return fmt.Errorf("attestation: in-TEE channel key missing — R2")
	}
	if len(c.ReportData) == 0 {
		return fmt.Errorf("attestation: report has no REPORT_DATA to bind")
	}
	if c.DebugEnabled {
		return fmt.Errorf("attestation: debug is enabled (policy.debug must be off)")
	}
	if c.MigrationEnabled {
		return fmt.Errorf("attestation: migration is enabled (must be off)")
	}
	if p.ExpectedType != "" && p.ExpectedType != "any" && !strings.EqualFold(c.TEEType, p.ExpectedType) {
		return fmt.Errorf("attestation: TEE type %q does not match requested %q", c.TEEType, p.ExpectedType)
	}
	if !tcbComponentsGTE(c.TCB, p.MinTCB) {
		return fmt.Errorf("attestation: reported TCB %d has a component below the minimum %d", c.TCB, p.MinTCB)
	}
	if !measurementAllowed(c.Measurement, p.Measurements) {
		return fmt.Errorf("attestation: launch measurement %q is not on the allowlist", c.Measurement)
	}
	if want := agent.BindingHash(p.Nonce, p.ChannelKey); !bytes.Equal(c.ReportData, want) {
		return fmt.Errorf("attestation: REPORT_DATA does not bind this run's nonce and channel key (replay/relay or wrong key)")
	}
	return nil
}

// tcbComponentsGTE compares SEV-SNP REPORTED_TCB values per component. The u64
// packs per-component SVNs (little-endian: bootloader, TEE, reserved×4, SNP,
// microcode), so a raw integer `<` is meaningless — the reserved bytes dominate.
// Every real component of `reported` must be >= the corresponding `minimum`.
func tcbComponentsGTE(reported, minimum uint64) bool {
	for _, shift := range []uint{0, 8, 48, 56} { // bootloader, TEE, SNP, microcode SVNs
		if byte(reported>>shift) < byte(minimum>>shift) {
			return false
		}
	}
	return true
}

// measurementAllowed returns true only on an exact (case-insensitive) match
// against a non-empty allowlist — an empty allowlist fails closed (R7).
func measurementAllowed(measurement string, allowlist []string) bool {
	for _, m := range allowlist {
		if strings.EqualFold(m, measurement) {
			return true
		}
	}
	return false
}
