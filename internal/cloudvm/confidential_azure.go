package cloudvm

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/types"
)

// endpointMAAFetch is a maaFetch that reads MAA evidence from the in-TEE agent's
// /attest endpoint — the same untrusted-channel transport GCP Confidential Space
// uses (csEndpointFetch), except the returned token is an Azure MAA token. Wired
// into azureAttester once the CVM's agent is reachable.
func endpointMAAFetch(baseURL string) maaFetch {
	return func(ctx context.Context, vm *VMInfo, sshKeyPath, sshUser string, nonce []byte) (maaEvidence, error) {
		ev, err := csEndpointFetch(baseURL)(ctx, vm, sshKeyPath, sshUser, nonce)
		if err != nil {
			return maaEvidence{}, err
		}
		return maaEvidence{token: ev.token, channelKey: ev.channelKey}, nil
	}
}

// azureDeps are the Azure confidential run's collaborators. The live operations
// (provision, start the agent on the CVM, endpoint reachability) are seams so the
// orchestration — the verify-before-seal ordering — is unit-testable without a
// cloud or a TEE.
type azureDeps struct {
	provider Provider
	keys     map[string]crypto.PublicKey // pinned MAA /certs keys
	issuer   string                      // pinned MAA instance issuer
	// startAgent provisions the agent on a booted CVM (scp the binary, start it,
	// open the NSG for its port) and returns its endpoint base URL.
	startAgent func(ctx context.Context, vm *VMInfo) (baseURL string, err error)
	waitReady  func(ctx context.Context, baseURL string) error
}

// executeAzureConfidential is the Azure orchestration core: provision the CVM,
// start the in-TEE agent, verify the MAA attestation over the untrusted endpoint,
// and only then seal the source/.env and run the sealed exchange. Any failure
// before a verified verdict tears the VM down and never ships a secret. Mirrors
// executeConfidentialSpace but on the SSH-VM + MAA path.
func executeAzureConfidential(ctx context.Context, d azureDeps, p *types.Plan) (*csRunState, error) {
	w := p.Workload

	payload, err := buildConfidentialPayload(w)
	if err != nil {
		return nil, fmt.Errorf("build workload payload: %w", err)
	}

	region := p.Constraints.Region
	opts := VMOptions{
		Name:             fmt.Sprintf("dispatcher-cvm-%s", adapter.SanitizeName(w.Name)),
		Region:           region,
		ConfidentialType: "sev-snp",
		Tags: map[string]string{
			"dispatcher-run-id": p.Metadata.ID,
			"dispatcher":        "true",
		},
	}

	dlog.L().Info("azurecvm.create.start", "run", p.Metadata.ID)
	vm, err := d.provider.CreateVM(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("provision confidential CVM: %w", err)
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

	// Verify MAA attestation BEFORE anything is sealed or shipped. The measurement
	// allowlist comes from the workload's confidential.measurements (operator-
	// pinned, since Azure's launch measurement is set by the CVM image).
	att := &azureAttester{keys: d.keys, issuer: d.issuer, isReady: true, fetch: endpointMAAFetch(baseURL)}
	result, err := att.Verify(ctx, vm, "", "", w.Requirements.Confidential)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}
	if !result.Verified {
		return nil, fmt.Errorf("attestation rejected: %s", result.Verdict)
	}
	dlog.L().Info("azurecvm.attested", "run", p.Metadata.ID, "vm_id", vm.ID, "measurement", result.Measurement)

	runRes, err := runSealedExchange(ctx, baseURL, result.ChannelKey, payload)
	if err != nil {
		return nil, fmt.Errorf("sealed run exchange: %w", err)
	}

	destroyOnErr = false
	return &csRunState{
		Provider:    d.provider.Name(),
		VMID:        vm.ID,
		Region:      region,
		Outputs:     w.Outputs,
		Result:      runRes,
		Attestation: result,
		CreatedAt:   time.Now().UTC(),
	}, nil
}
