package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"

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

// Attester fetches and verifies a TEE's attestation evidence for a booted VM.
// Implementations are per-provider. The verification crypto is unit-testable;
// only the fetch needs a live TEE.
type Attester interface {
	// Verify checks the running VM's attestation against the run's confidential
	// requirement (TEE type, measurement allowlist, minimum TCB). A returned
	// Verified=false (or an error) means the run must not proceed.
	Verify(ctx context.Context, vm *VMInfo, sshKeyPath, sshUser string, req types.ConfidentialRequirement) (AttestationResult, error)
}

// attesters maps a provider to its attestation verifier. The verification crypto
// (SEV-SNP report + AMD chain for GCP/AWS, MAA token for Azure) is built and
// tested, but each attester reports not-ready until its live evidence fetch (the
// guest-agent measured image) is wired — so a confidential run that requires
// attestation still fails closed *before* provisioning (see the preflight).
// Tests inject ready attesters via withAttester.
var attesters = map[ProviderID]Attester{
	ProviderGCP:   &snpAttester{roots: amdRoots},
	ProviderAWS:   &snpAttester{roots: amdRoots},
	ProviderAzure: &azureAttester{},
}

func attesterFor(id ProviderID) Attester { return attesters[id] }

// attesterReady reports whether an attester can actually fetch evidence. An
// attester that doesn't expose readiness (e.g. a test stub) is treated as ready.
func attesterReady(a Attester) bool {
	if r, ok := a.(interface{ ready() bool }); ok {
		return r.ready()
	}
	return true
}

// verifyConfidential runs the provider's attester for a confidential run after
// the VM is reachable. It returns the recorded result on success, (nil, nil)
// when the run isn't confidential or attestation is off, and an error that must
// abort the run (and destroy the VM) on rejection or failure.
func verifyConfidential(ctx context.Context, provider ProviderID, vm *VMInfo, sshKey, sshUser string, c types.ConfidentialRequirement) (*AttestationResult, error) {
	if !c.Required {
		return nil, nil
	}
	if c.Attestation == "off" {
		// Explicit opt-out (N4): provision the TEE (encrypted memory) without
		// verification. Record an unverified verdict so status/diagnose are honest.
		return &AttestationResult{Verified: false, Verdict: "attestation off — provisioned TEE without verification (N4)"}, nil
	}
	att := attesterFor(provider)
	if att == nil {
		// Preflight should already have failed closed; belt and suspenders.
		return nil, fmt.Errorf("no attestation verifier available for %s", provider)
	}
	result, err := att.Verify(ctx, vm, sshKey, sshUser, c)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}
	if !result.Verified {
		return nil, fmt.Errorf("attestation rejected: %s", result.Verdict)
	}
	return &result, nil
}

// confidentialAttestationPreflight fails closed before provisioning when a
// confidential run requires attestation but no verifier exists for the provider.
// When a verifier exists, the real check runs post-boot (the VM must be running
// to produce a report). `attestation: off` skips both.
func confidentialAttestationPreflight(w types.WorkloadSpec, provider ProviderID) error {
	c := w.Requirements.Confidential
	if !c.Required || c.Attestation == "off" {
		return nil
	}
	a := attesterFor(provider)
	if a == nil {
		return fmt.Errorf("confidential attestation is required but no attestation verifier is available for %s; "+
			"set `confidential.attestation: off` to provision the TEE without verification (see docs/confidential-computing.md)", provider)
	}
	if !attesterReady(a) {
		return fmt.Errorf("confidential attestation is required for %s but its evidence channel is not deployed yet "+
			"(the verifier is built and tested, but fetching a live report needs the guest-agent measured image — see docs/confidential-computing.md §6); "+
			"set `confidential.attestation: off` to provision the TEE without verification", provider)
	}
	return nil
}
