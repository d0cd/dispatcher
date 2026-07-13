package cloudvm

import (
	"context"
	"fmt"
	"os"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/types"
)

// azureSNPDeps are the Azure direct-SNP confidential run's collaborators. The
// agent is baked into the measured image (its dm-verity roothash is in PCR11), so
// there is no scp/start — the parent just boots the pinned image and the agent
// auto-starts.
type azureSNPDeps struct {
	provider   Provider
	image      string // measured gallery image (agent in a dm-verity root -> PCR11)
	pcrs       map[int]string
	sshPubKey  string
	sshUser    string
	startAgent func(ctx context.Context, vm *VMInfo) (string, error)
	waitReady  func(ctx context.Context, baseURL string) error
}

// executeAzureSNPConfidential is the Azure measured-boot orchestration: the shared
// SSH-VM flow, provisioning a CVM from the pinned measured image (Secure Boot off,
// unsigned UKI) and verifying the direct SNP+vTPM evidence, pinning PCR11.
func executeAzureSNPConfidential(ctx context.Context, d azureSNPDeps, p *types.Plan) (*confidentialRunState, error) {
	deps := sshConfidentialDeps{
		provider: d.provider, image: d.image, confidential: "sev-snp", secureBootOff: true,
		sshPubKey: d.sshPubKey, sshUser: d.sshUser,
		startAgent: d.startAgent, waitReady: d.waitReady,
		verify: func(ctx context.Context, _ *VMInfo, baseURL string, req types.ConfidentialRequirement) (attest.AttestationResult, error) {
			return attest.NewAzureSNPAttester(d.pcrs, baseURL).Verify(ctx, req)
		},
	}
	return executeSSHConfidential(ctx, deps, p, fmt.Sprintf("dispatcher-azsnp-%s", adapter.SanitizeName(p.Workload.Name)))
}

// azureSNPStartAgent returns a startAgent for a booted measured CVM: the agent is
// baked into the image and auto-starts, so it only opens the NSG for the agent
// port. Unlike the MAA path there is no scp — the running agent IS the measured
// one (PCR11 attests the dm-verity root that carries it).
func azureSNPStartAgent(egressCIDR string, provider Provider) func(context.Context, *VMInfo) (string, error) {
	return func(ctx context.Context, vm *VMInfo) (string, error) {
		if op, ok := provider.(azurePortOpener); ok && egressCIDR != "" {
			if err := op.OpenAgentPort(ctx, vm.Name, csAgentPort, egressCIDR); err != nil {
				return "", fmt.Errorf("open agent port: %w", err)
			}
		}
		return fmt.Sprintf("http://%s:%d", vm.IP, csAgentPort), nil
	}
}

// AzureSNPConfidentialAdapter runs a workload on an Azure confidential VM whose
// agent is MEASURED: the image bakes the agent into a dm-verity root whose roothash
// is in PCR11, verified directly (SNP report + vTPM quote, no MAA). This closes the
// agent-not-measured caveat on Azure. See docs/confidential-azure-uki.md.
type AzureSNPConfidentialAdapter struct {
	confidentialVMAdapter
	image string // measured gallery image id (DISPATCHER_AZURE_SNP_IMAGE)
	pcrs  map[int]string
}

// NewAzureSNPConfidentialAdapter builds the adapter. image is the pinned measured
// gallery image; pcrs pins the PCRs (PCR11 = the agent-carrying dm-verity root).
func NewAzureSNPConfidentialAdapter(provider Provider, image string, pcrs map[int]string, cfg Config) *AzureSNPConfidentialAdapter {
	return &AzureSNPConfidentialAdapter{
		confidentialVMAdapter: confidentialVMAdapter{
			targetID: string(cfg.ProviderID) + "-snp",
			provider: provider, config: cfg,
			costAssumption: "confidential (SEV-SNP) CVM, measured image",
		},
		image: image, pcrs: pcrs,
	}
}

func (a *AzureSNPConfidentialAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	if a.image == "" || len(a.pcrs) == 0 {
		return nil, fmt.Errorf("azure-snp adapter needs a measured gallery image and a pinned PCR11 (build with deploy/azure-uki/mkosi)")
	}
	a.resolveRegion(p)
	keyPath, err := generateSSHKey(ctx, p.Metadata.ID)
	if err != nil {
		return nil, fmt.Errorf("generate ssh key: %w", err)
	}
	defer func() {
		_ = os.Remove(keyPath)
		_ = os.Remove(keyPath + ".pub")
	}()

	egress, err := detectEgressCIDR(ctx)
	if err != nil {
		return nil, fmt.Errorf("scope confidential agent firewall: %w", err)
	}
	deps := azureSNPDeps{
		provider:   a.provider,
		image:      a.image,
		pcrs:       a.pcrs,
		sshPubKey:  keyPath + ".pub",
		sshUser:    a.config.SSHUser,
		startAgent: azureSNPStartAgent(egress, a.provider),
		waitReady:  waitForAgentEndpoint,
	}
	state, err := executeAzureSNPConfidential(ctx, deps, p)
	if err != nil {
		return nil, err
	}
	return &adapter.RunHandle{ID: state.VMID, TargetID: a.targetID, State: state}, nil
}
