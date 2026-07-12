package cloudvm

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	statedir "github.com/d0cd/dispatcher/internal/state"
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
	targetID string
	provider Provider
	image    string // measured gallery image id (DISPATCHER_AZURE_SNP_IMAGE)
	pcrs     map[int]string
	config   Config
}

// NewAzureSNPConfidentialAdapter builds the adapter. image is the pinned measured
// gallery image; pcrs pins the PCRs (PCR11 = the agent-carrying dm-verity root).
func NewAzureSNPConfidentialAdapter(provider Provider, image string, pcrs map[int]string, cfg Config) *AzureSNPConfidentialAdapter {
	return &AzureSNPConfidentialAdapter{
		targetID: string(cfg.ProviderID) + "-snp", provider: provider, image: image, pcrs: pcrs, config: cfg,
	}
}

func (a *AzureSNPConfidentialAdapter) ID() string { return a.targetID }

func (a *AzureSNPConfidentialAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	if a.image == "" || len(a.pcrs) == 0 {
		return nil, fmt.Errorf("azure-snp adapter needs a measured gallery image and a pinned PCR11 (build with deploy/azure-uki/mkosi)")
	}
	region := p.Constraints.Region
	if region == "" {
		region = a.config.Region
	}
	if rp, ok := a.provider.(regionalProvider); ok && region != "" {
		rp.SetRegion(region)
	}
	keyPath, err := generateSSHKey(ctx, p.Metadata.ID)
	if err != nil {
		return nil, fmt.Errorf("generate ssh key: %w", err)
	}
	defer func() {
		_ = os.Remove(keyPath)
		_ = os.Remove(keyPath + ".pub")
	}()

	deps := azureSNPDeps{
		provider:   a.provider,
		image:      a.image,
		pcrs:       a.pcrs,
		sshPubKey:  keyPath + ".pub",
		sshUser:    a.config.SSHUser,
		startAgent: azureSNPStartAgent(detectEgressCIDR(ctx), a.provider),
		waitReady:  waitForAgentEndpoint,
	}
	state, err := executeAzureSNPConfidential(ctx, deps, p)
	if err != nil {
		return nil, err
	}
	return &adapter.RunHandle{ID: state.VMID, TargetID: a.targetID, State: state}, nil
}

func (a *AzureSNPConfidentialAdapter) Validate(ctx context.Context, _ types.WorkloadSpec) (types.ValidationResult, error) {
	v := types.ValidationResult{
		Schema: types.ValidationPass, PackageBuild: types.ValidationPass,
		TargetCapabilities: types.ValidationPass, Credentials: types.ValidationPass,
		Quota: types.ValidationSkipped, Network: types.ValidationPass,
		Policy: types.ValidationPass, CostEstimate: types.ValidationPass, CleanupPlan: types.ValidationPass,
	}
	if err := a.provider.CheckCLI(ctx); err != nil {
		v.Credentials = types.ValidationFail
		return v, fmt.Errorf("provider CLI check failed: %w", err)
	}
	return v, nil
}

func (a *AzureSNPConfidentialAdapter) EstimateCost(_ context.Context, w types.WorkloadSpec) (types.CostEstimate, error) {
	hours := 1.0
	if w.DetectedKind == types.WorkloadKindService {
		hours = 24.0
	}
	total := providerBaseRate(a.config.ProviderID) * hours
	return types.CostEstimate{
		Value: float64(int(total*1000)) / 1000, Currency: "USD", Confidence: types.ConfidenceMedium,
		Assumptions: []string{fmt.Sprintf("assumes %.0fh runtime", hours), "confidential (SEV-SNP) CVM, measured image"},
		Exclusions:  []string{"excludes network egress", "excludes storage"},
	}, nil
}

func (a *AzureSNPConfidentialAdapter) Prepare(context.Context, *types.Plan) error { return nil }

func (a *AzureSNPConfidentialAdapter) Status(_ context.Context, h *adapter.RunHandle) (types.RunState, error) {
	if h.State.(*confidentialRunState).Result.ExitCode != 0 {
		return types.RunStateExecutionFailed, nil
	}
	return types.RunStateCompleted, nil
}

func (a *AzureSNPConfidentialAdapter) FailureDetails(h *adapter.RunHandle) adapter.FailureDetails {
	state, ok := h.State.(*confidentialRunState)
	if !ok {
		return adapter.FailureDetails{Message: "no confidential run state"}
	}
	fd := adapter.FailureDetails{ExitCode: state.Result.ExitCode}
	if state.Result.ExitCode != 0 {
		fd.Message = fmt.Sprintf("confidential workload exited with code %d", state.Result.ExitCode)
	}
	return fd
}

func (a *AzureSNPConfidentialAdapter) Logs(_ context.Context, h *adapter.RunHandle, w io.Writer) error {
	state := h.State.(*confidentialRunState)
	if len(state.Result.Stdout) > 0 {
		_, _ = w.Write(state.Result.Stdout)
	}
	if len(state.Result.Stderr) > 0 {
		_, _ = w.Write(state.Result.Stderr)
	}
	return nil
}

func (a *AzureSNPConfidentialAdapter) Artifacts(_ context.Context, h *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
	state := h.State.(*confidentialRunState)
	if len(state.Result.OutputsTarGz) == 0 {
		return nil, nil
	}
	indexKey := h.RunID
	if indexKey == "" {
		indexKey = h.ID
	}
	dest, err := statedir.Subdir(filepath.Join("runs", indexKey, "artifacts"))
	if err != nil {
		return nil, fmt.Errorf("create artifacts dir: %w", err)
	}
	if err := agent.UnTarGz(state.Result.OutputsTarGz, dest); err != nil {
		return nil, fmt.Errorf("extract outputs: %w", err)
	}
	var refs []adapter.ArtifactRef
	_ = filepath.Walk(dest, func(pth string, info os.FileInfo, _ error) error {
		if info == nil || info.IsDir() {
			return nil
		}
		refs = append(refs, adapter.ArtifactRef{Name: filepath.Base(pth), Path: pth, Size: info.Size()})
		return nil
	})
	return refs, nil
}

func (a *AzureSNPConfidentialAdapter) Terminate(context.Context, *adapter.RunHandle) error {
	return nil
}

func (a *AzureSNPConfidentialAdapter) Cleanup(ctx context.Context, h *adapter.RunHandle) (*adapter.CleanupResult, error) {
	state := h.State.(*confidentialRunState)
	if err := a.provider.DestroyVM(ctx, state.VMID); err != nil {
		return &adapter.CleanupResult{Success: false, Errors: []string{err.Error()}}, nil
	}
	return &adapter.CleanupResult{Success: true, ResourcesCleaned: []string{state.VMID}}, nil
}
