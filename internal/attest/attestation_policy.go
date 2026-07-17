package attest

import (
	"strings"
)

// Claims is the normalized, provider-agnostic set of facts a verifier extracts
// from a TEE's attestation evidence (after it has already checked the
// signature/cert chain to the hardware root). The per-cloud verifiers enforce the
// run's requirements (measurement allowlist, TCB floor, debug/migration policy,
// freshness/binding) directly; this projection is what the SNP report parser
// exposes.
type Claims struct {
	TEEType          string // "sev" | "sev-snp" | "tdx"
	Measurement      string // hex launch measurement
	DebugEnabled     bool   // policy bit: debugging allowed
	MigrationEnabled bool   // policy bit: live migration allowed
	TCB              uint64 // reported TCB/firmware version (higher = newer)
	ReportData       []byte // the report's REPORT_DATA / runtime-data binding
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
