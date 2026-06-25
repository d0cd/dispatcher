package cloudvm

import (
	"context"
	"fmt"

	"github.com/d0cd/dispatcher/internal/types"
)

// AttestationResult records the outcome of verifying a TEE's attestation report.
// Persisted on the run state so `diagnose`/`status` can show whether a
// confidential run was actually proven, and which TEE type.
type AttestationResult struct {
	Verified bool   `json:"verified"`
	Type     string `json:"type,omitempty"`    // the TEE type proven (e.g. "sev-snp")
	Verdict  string `json:"verdict,omitempty"` // human-readable reason
}

// Attester fetches and verifies a TEE's attestation evidence for a booted VM.
// Implementations are per-provider. The verification crypto is unit-testable;
// only the fetch needs a live TEE.
type Attester interface {
	// Verify checks the running VM's attestation against the requested TEE type
	// (reqType may be "" or "any"). A returned Verified=false (or an error) means
	// the run must not proceed.
	Verify(ctx context.Context, vm *VMInfo, sshKeyPath, sshUser, reqType string) (AttestationResult, error)
}

// attesters maps a provider to its attestation verifier. It is empty until a
// real verifier lands — so a confidential run that requires attestation fails
// closed *before* provisioning (rather than booting, and billing, a VM it can't
// attest). Real verifiers register here; tests inject via withAttester.
var attesters = map[ProviderID]Attester{}

func attesterFor(id ProviderID) Attester { return attesters[id] }

// verifyConfidential runs the provider's attester for a confidential run after
// the VM is reachable. It returns the recorded result on success, (nil, nil)
// when the run isn't confidential or attestation is off, and an error that must
// abort the run (and destroy the VM) on rejection or failure.
func verifyConfidential(ctx context.Context, provider ProviderID, vm *VMInfo, sshKey, sshUser string, c types.ConfidentialRequirement) (*AttestationResult, error) {
	if !c.Required || c.Attestation == "off" {
		return nil, nil
	}
	att := attesterFor(provider)
	if att == nil {
		// Preflight should already have failed closed; belt and suspenders.
		return nil, fmt.Errorf("no attestation verifier available for %s", provider)
	}
	result, err := att.Verify(ctx, vm, sshKey, sshUser, c.Type)
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
	if c.Required && c.Attestation != "off" && attesterFor(provider) == nil {
		return fmt.Errorf("confidential attestation is required but no attestation verifier is available for %s yet; "+
			"set `confidential.attestation: off` to provision the TEE without verification (see docs/confidential-computing.md)", provider)
	}
	return nil
}
