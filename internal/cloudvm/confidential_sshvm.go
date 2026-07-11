package cloudvm

import (
	"context"
	"fmt"
	"time"

	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/types"
)

// runSealedExchange is a seam over agent.RunSealedExchange so adapter
// orchestration tests can drive the flow without a live in-TEE agent (the agent
// + exchange are tested end-to-end in the attest package).
var runSealedExchange = agent.RunSealedExchange

// sshConfidentialDeps are the collaborators for an SSH-VM confidential run (Azure
// MAA, AWS SEV-SNP). The provider-specific verification is a closure so the same
// orchestration serves both; the live ops (provision, start-agent, endpoint
// reachability) are seams so the verify-before-seal ordering is unit-testable.
type sshConfidentialDeps struct {
	provider Provider
	image    string // optional VM image override (AWS pins a SEV-SNP 24.04 AMI)
	// confidential is VMOptions.ConfidentialType: "sev-snp" for a memory-encrypted
	// CVM (Azure MAA, AWS SEV-SNP), or "" for a Nitro Enclaves parent (the parent
	// is a plain instance — the measured enclave it launches is the TEE).
	confidential string
	enclave      bool   // request Nitro Enclaves support on the parent
	instanceType string // optional; a Nitro parent pins an enclave-capable type
	sshPubKey    string
	sshUser      string
	startAgent   func(ctx context.Context, vm *VMInfo) (baseURL string, err error)
	waitReady    func(ctx context.Context, baseURL string) error
	// verify runs the provider's attester over the agent endpoint (MAA for Azure,
	// raw SEV-SNP for AWS, Nitro doc for enclaves) and returns the verdict + the
	// channel key to seal to.
	verify func(ctx context.Context, vm *VMInfo, baseURL string, req types.ConfidentialRequirement) (attest.AttestationResult, error)
}

// executeSSHConfidential is the shared SSH-VM confidential orchestration:
// provision the VM, start the in-TEE agent, verify attestation over the untrusted
// endpoint, and only then seal source/.env and run the sealed exchange. Any
// failure before a verified verdict tears the VM down and never ships a secret.
func executeSSHConfidential(ctx context.Context, d sshConfidentialDeps, p *types.Plan, vmName string) (*confidentialRunState, error) {
	w := p.Workload

	payload, err := buildConfidentialPayload(w)
	if err != nil {
		return nil, fmt.Errorf("build workload payload: %w", err)
	}

	region := p.Constraints.Region
	opts := VMOptions{
		Name:             vmName,
		Region:           region,
		Image:            d.image,
		InstanceType:     d.instanceType,
		ConfidentialType: d.confidential,
		EnclaveEnabled:   d.enclave,
		SSHKeyPath:       d.sshPubKey,
		SSHUser:          d.sshUser,
		Tags: map[string]string{
			"dispatcher-run-id": p.Metadata.ID,
			"dispatcher":        "true",
		},
	}

	dlog.L().Info("sshconf.create.start", "run", p.Metadata.ID, "provider", string(d.provider.Name()))
	vm, err := d.provider.CreateVM(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("provision confidential VM: %w", err)
	}
	destroyOnErr := true
	defer func() {
		if !destroyOnErr {
			return
		}
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = d.provider.DestroyVM(cctx, vm.ID)
	}()

	baseURL, err := d.startAgent(ctx, vm)
	if err != nil {
		return nil, fmt.Errorf("start in-TEE agent: %w", err)
	}
	if err := d.waitReady(ctx, baseURL); err != nil {
		return nil, fmt.Errorf("confidential agent endpoint not reachable: %w", err)
	}

	// Verify attestation BEFORE anything is sealed or shipped.
	result, err := d.verify(ctx, vm, baseURL, w.Requirements.Confidential)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}
	if !result.Verified {
		return nil, fmt.Errorf("attestation rejected: %s", result.Verdict)
	}
	dlog.L().Info("sshconf.attested", "run", p.Metadata.ID, "vm_id", vm.ID, "measurement", result.Measurement)

	runRes, err := runSealedExchange(ctx, baseURL, result.ChannelKey, payload)
	if err != nil {
		return nil, fmt.Errorf("sealed run exchange: %w", err)
	}

	destroyOnErr = false
	return &confidentialRunState{
		Provider:    d.provider.Name(),
		VMID:        vm.ID,
		Region:      region,
		Outputs:     w.Outputs,
		Result:      runRes,
		Attestation: result,
		CreatedAt:   time.Now().UTC(),
	}, nil
}
