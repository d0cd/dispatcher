package cloudvm

import (
	"context"
	"fmt"

	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/types"
)

// verifyConfidential is the CloudVMAdapter (SSH-VM) path's attestation step. With
// attestation on, GCP/Azure/AWS runs are routed to their confidential adapters
// (which verify + seal), so this path only records the attestation:off verdict —
// provision a TEE without verification — and fails closed for an attestation-on
// run it should never have received.
func verifyConfidential(_ context.Context, provider ProviderID, _ *VMInfo, _, _ string, c types.ConfidentialRequirement) (*attest.AttestationResult, error) {
	if !c.Required {
		return nil, nil
	}
	if c.Attestation == "off" {
		return &attest.AttestationResult{Verified: false, Verdict: "attestation off — provisioned TEE without verification (N4)"}, nil
	}
	return nil, fmt.Errorf("confidential attestation required on %s but this SSH-VM path has no verifier; a confidential adapter should have handled it", provider)
}

// confidentialAttestationPreflight fails closed before provisioning when a
// confidential run on the SSH-VM path requires attestation. This path has no
// verifier — attestation-on runs are routed to the provider's confidential
// adapter — so reaching here with attestation on must never provision an
// unattested TEE. `attestation: off` is the explicit escape hatch.
func confidentialAttestationPreflight(w types.WorkloadSpec, provider ProviderID) error {
	c := w.Requirements.Confidential
	if !c.Required || c.Attestation == "off" {
		return nil
	}
	return fmt.Errorf("confidential attestation is required but no verifier is available on the SSH-VM path for %s; "+
		"attestation-on runs are routed to the confidential adapter — set `confidential.attestation: off` "+
		"to provision the TEE without verification (see docs/confidential-computing.md)", provider)
}
