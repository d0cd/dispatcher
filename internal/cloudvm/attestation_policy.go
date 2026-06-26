package cloudvm

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"strings"
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

// bindingHash is the value that must appear in REPORT_DATA: SHA-512 over the
// per-run nonce concatenated with the in-TEE channel key. SHA-512 is 64 bytes,
// matching SEV-SNP's REPORT_DATA field.
func bindingHash(nonce, channelKey []byte) []byte {
	h := sha512.New()
	h.Write(nonce)
	h.Write(channelKey)
	return h.Sum(nil)
}

// applyPolicy enforces R5–R8 and freshness/binding (R1/R2) on extracted claims.
// The caller must already have verified the signature chain (R3/R4). Returns nil
// only when every check passes; any failure must abort and destroy the VM.
func applyPolicy(c Claims, p VerificationPolicy) error {
	if c.DebugEnabled {
		return fmt.Errorf("attestation: debug is enabled (policy.debug must be off)")
	}
	if c.MigrationEnabled {
		return fmt.Errorf("attestation: migration is enabled (must be off)")
	}
	if p.ExpectedType != "" && p.ExpectedType != "any" && !strings.EqualFold(c.TEEType, p.ExpectedType) {
		return fmt.Errorf("attestation: TEE type %q does not match requested %q", c.TEEType, p.ExpectedType)
	}
	if c.TCB < p.MinTCB {
		return fmt.Errorf("attestation: reported TCB %d below minimum %d", c.TCB, p.MinTCB)
	}
	if !measurementAllowed(c.Measurement, p.Measurements) {
		return fmt.Errorf("attestation: launch measurement %q is not on the allowlist", c.Measurement)
	}
	if want := bindingHash(p.Nonce, p.ChannelKey); !bytes.Equal(c.ReportData, want) {
		return fmt.Errorf("attestation: REPORT_DATA does not bind this run's nonce and channel key (replay/relay or wrong key)")
	}
	return nil
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
