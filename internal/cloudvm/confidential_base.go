package cloudvm

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	statedir "github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// confidentialVMAdapter carries the fields and TargetAdapter methods shared by
// the SSH-VM confidential adapters (AWS SEV-SNP, Azure MAA, Azure measured-SNP,
// AWS Nitro). Each embeds it and adds its own Execute plus provisioning fields,
// so a change to the shared post-run lifecycle (Status/Logs/Artifacts/Cleanup)
// lands in one place instead of four. EstimateCost's only per-adapter variation
// is the TEE-type assumption line, carried in costAssumption.
//
// The GCP Confidential Space adapter is intentionally NOT built on this: it
// reaches its provider via a deps struct and reaps a per-run agent-port firewall
// in Cleanup, so its lifecycle genuinely differs.
type confidentialVMAdapter struct {
	targetID       string
	provider       Provider
	config         Config
	costAssumption string
}

func (a *confidentialVMAdapter) ID() string { return a.targetID }

// resolveRegion picks the run's region (falling back to the config default) and
// applies it to a regional provider. Returns the resolved region for callers
// that also need it (e.g. AMI resolution).
func (a *confidentialVMAdapter) resolveRegion(p *types.Plan) string {
	region := p.Constraints.Region
	if region == "" {
		region = a.config.Region
	}
	if rp, ok := a.provider.(regionalProvider); ok && region != "" {
		rp.SetRegion(region)
	}
	return region
}

func (a *confidentialVMAdapter) Validate(ctx context.Context, _ types.WorkloadSpec) (types.ValidationResult, error) {
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

func (a *confidentialVMAdapter) EstimateCost(_ context.Context, w types.WorkloadSpec) (types.CostEstimate, error) {
	hours := 1.0
	if w.DetectedKind == types.WorkloadKindService {
		hours = 24.0
	}
	total := providerBaseRate(a.config.ProviderID) * hours
	return types.CostEstimate{
		Value: float64(int(total*1000)) / 1000, Currency: "USD", Confidence: types.ConfidenceMedium,
		Assumptions: []string{fmt.Sprintf("assumes %.0fh runtime", hours), a.costAssumption},
		Exclusions:  []string{"excludes network egress", "excludes storage"},
	}, nil
}

func (a *confidentialVMAdapter) Prepare(context.Context, *types.Plan) error { return nil }

func (a *confidentialVMAdapter) Status(_ context.Context, h *adapter.RunHandle) (types.RunState, error) {
	if h.State.(*confidentialRunState).Result.ExitCode != 0 {
		return types.RunStateExecutionFailed, nil
	}
	return types.RunStateCompleted, nil
}

func (a *confidentialVMAdapter) FailureDetails(h *adapter.RunHandle) adapter.FailureDetails {
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

func (a *confidentialVMAdapter) Logs(_ context.Context, h *adapter.RunHandle, w io.Writer) error {
	state := h.State.(*confidentialRunState)
	if len(state.Result.Stdout) > 0 {
		_, _ = w.Write(state.Result.Stdout)
	}
	if len(state.Result.Stderr) > 0 {
		_, _ = w.Write(state.Result.Stderr)
	}
	return nil
}

func (a *confidentialVMAdapter) Artifacts(_ context.Context, h *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
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

func (a *confidentialVMAdapter) Terminate(context.Context, *adapter.RunHandle) error { return nil }

func (a *confidentialVMAdapter) Cleanup(ctx context.Context, h *adapter.RunHandle) (*adapter.CleanupResult, error) {
	state := h.State.(*confidentialRunState)
	if err := a.provider.DestroyVM(ctx, state.VMID); err != nil {
		return &adapter.CleanupResult{Success: false, Errors: []string{err.Error()}}, nil
	}
	return &adapter.CleanupResult{Success: true, ResourcesCleaned: []string{state.VMID}}, nil
}
