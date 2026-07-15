package cloudvm

import (
	"context"
	"fmt"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/types"
)

// OCIConfidentialAdapter is reserved for OCI's provider-specific BYAS
// attestation flow. It deliberately fails closed until OCI evidence retrieval,
// certificate-chain verification, report-data binding, and live hardware tests
// are implemented. In particular, AWS's VLEK verifier is not interchangeable
// with OCI BYAS and bare-metal confidentiality is not a guest-scoped TEE.
type OCIConfidentialAdapter struct {
	confidentialVMAdapter
}

// NewOCIConfidentialAdapter keeps the API stable for callers while ensuring an
// experimental configuration cannot release credentials based on assumed
// evidence semantics.
func NewOCIConfidentialAdapter(provider Provider, _ string, cfg Config) *OCIConfidentialAdapter {
	return &OCIConfidentialAdapter{confidentialVMAdapter: confidentialVMAdapter{
		targetID: string(cfg.ProviderID) + "-confidential",
		provider: provider,
		config:   cfg,
	}}
}

func (a *OCIConfidentialAdapter) Execute(context.Context, *types.Plan) (*adapter.RunHandle, error) {
	return nil, fmt.Errorf("OCI confidential attestation is not implemented: OCI BYAS evidence and certificate-chain verification must be live-validated before secrets can be released")
}
