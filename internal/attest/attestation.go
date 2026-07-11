package attest

import (
	"context"
	"encoding/json"

	"github.com/d0cd/dispatcher/internal/types"
)

// AttestationResult records the outcome of verifying a TEE's attestation report.
// Persisted on the run state so `diagnose`/`status` can show whether a
// confidential run was actually proven, and which TEE type.
type AttestationResult struct {
	Verified    bool   `json:"verified"`
	Type        string `json:"type,omitempty"`        // the TEE type proven (e.g. "sev-snp")
	Measurement string `json:"measurement,omitempty"` // hex launch measurement (R13/G5)
	TCB         uint64 `json:"tcb,omitempty"`         // reported TCB version
	Nonce       string `json:"nonce,omitempty"`       // hex per-run challenge
	Verdict     string `json:"verdict,omitempty"`     // human-readable reason
	// ChannelKey is the verified, attestation-bound in-TEE sealing public key
	// (CS path). It exists only in-memory during Execute so the adapter can seal
	// secrets to it; it is never persisted (the run is over before it matters).
	ChannelKey []byte `json:"-"`
}

// AttestationFromHandleState extracts the attestation verdict from a persisted
// run's adapter HandleState, or nil when the run isn't a confidential cloud VM
// (or the state predates attestation). Lets status/diagnose surface the verdict
// without depending on the rest of CloudVMState.
func AttestationFromHandleState(raw json.RawMessage) *AttestationResult {
	if len(raw) == 0 {
		return nil
	}
	var s struct {
		Attestation *AttestationResult `json:"attestation"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return s.Attestation
}

// Attester fetches and verifies a TEE's attestation evidence over the in-TEE
// agent's endpoint. Implementations are per-provider (CS token, MAA token, raw
// SEV-SNP report). A returned Verified=false (or an error) means the run must not
// proceed. The verification crypto is unit-testable; only the fetch needs a live
// TEE.
type Attester interface {
	Verify(ctx context.Context, req types.ConfidentialRequirement) (AttestationResult, error)
}
