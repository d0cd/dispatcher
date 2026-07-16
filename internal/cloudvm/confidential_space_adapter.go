package cloudvm

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/dlog"
	statedir "github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// ConfidentialSpaceAdapter runs a workload on GCP Confidential Space: the
// workload is a measured container, attested by image digest, reached over an
// untrusted TCP channel that is made safe by verify-before-seal and HPKE sealing
// (docs/confidential-space-execution.md). It is a distinct execution path from
// the SSH-VM CloudVMAdapter — no SSH, no rsync, no PID; the run is synchronous
// (the sealed exchange blocks until the workload finishes).
type ConfidentialSpaceAdapter struct {
	targetID string
	deps     csDeps
	config   Config
}

// csDeps are the ConfidentialSpaceAdapter's collaborators. The live-infra
// operations (image build+push, VM lifecycle, endpoint reachability) are seams
// so the orchestration — the security-critical verify-before-seal ordering — is
// unit-testable without a cloud or a TEE.
type csDeps struct {
	provider Provider
	keys     map[string]crypto.PublicKey // trusted Google JWKS
	// buildImage builds the measured agent image for the workload and pushes it,
	// returning (imageReference, imageDigest). The digest is the attested identity
	// dispatcher allowlists.
	buildImage func(ctx context.Context, w types.WorkloadSpec) (imageRef, imageDigest string, err error)
	// baseURL is the in-TEE agent's endpoint for a booted VM (http://IP:port).
	baseURL func(vm *VMInfo) string
	// waitReady blocks until the agent endpoint accepts connections.
	waitReady func(ctx context.Context, baseURL string) error
	// egressCIDR resolves the source range the agent-port firewall is scoped to
	// (dispatcher's egress IP). Nil skips the firewall (e.g. in unit tests).
	egressCIDR func(ctx context.Context) (string, error)
}

// agentFirewaller is an optional Provider capability: manage the per-run firewall
// that opens the in-TEE agent's port. The provider owns the CLI; the adapter owns
// the lifecycle (create at provision via VMOptions, delete at Cleanup).
type agentFirewaller interface {
	deleteAgentFirewall(ctx context.Context, name string) error
}

// confidentialRunState is the persisted handle state for a confidential run,
// shared by the confidential backends (GCP Confidential Space, azure-snp, AWS Nitro).
// The run is already finished by the time Execute returns, so this carries the
// captured result plus what Cleanup needs to tear the VM down. ImageRef is only
// set on the GCP container path.
type confidentialRunState struct {
	Provider    ProviderID               `json:"provider"`
	VMID        string                   `json:"vmId"`
	Region      string                   `json:"region"`
	ImageRef    string                   `json:"imageRef"`
	Outputs     []string                 `json:"outputs,omitempty"`
	Result      agent.Result             `json:"result"`
	Attestation attest.AttestationResult `json:"attestation"`
	CreatedAt   time.Time                `json:"createdAt"`
}

func (s *confidentialRunState) MarshalHandleState() (json.RawMessage, error) { return json.Marshal(s) }

// NewConfidentialSpaceAdapter builds an adapter for GCP Confidential Space.
// buildImage is injected because packaging the measured image is provider- and
// environment-specific; the remaining collaborators default to live behaviour.
func NewConfidentialSpaceAdapter(provider Provider, keys map[string]crypto.PublicKey, buildImage func(context.Context, types.WorkloadSpec) (string, string, error), cfg Config) *ConfidentialSpaceAdapter {
	return &ConfidentialSpaceAdapter{
		targetID: string(cfg.ProviderID) + "-confidential-space",
		config:   cfg,
		deps: csDeps{
			provider:   provider,
			keys:       keys,
			buildImage: buildImage,
			baseURL:    defaultCSBaseURL,
			waitReady:  waitForAgentEndpoint,
			egressCIDR: detectEgressCIDR,
		},
	}
}

func (a *ConfidentialSpaceAdapter) ID() string { return a.targetID }

// executeConfidentialSpace is the orchestration core: build the measured image,
// provision the CS VM pinned to its digest, verify attestation over the untrusted
// endpoint, and only then seal the source/.env and run the exchange. Any failure
// before a verified verdict tears the VM down and never ships a secret.
func executeConfidentialSpace(ctx context.Context, d csDeps, p *types.Plan) (*confidentialRunState, error) {
	w := p.Workload

	// Fail closed on GPU, as the plain adapter does: Confidential Space forces a
	// CPU-only SEV SKU and has no GPU inventory, so a GPU workload reaching here
	// (e.g. a hand-forced target bypassing feasibility) must be refused rather
	// than silently run CPU-only on a costly confidential VM. InstanceType is
	// unset on this path, so this refuses whenever the workload requires a GPU.
	if err := validateGPUInstance(w, ""); err != nil {
		return nil, err
	}

	payload, err := buildConfidentialPayload(w)
	if err != nil {
		return nil, fmt.Errorf("build workload payload: %w", err)
	}

	imageRef, imageDigest, err := d.buildImage(ctx, w)
	if err != nil {
		return nil, fmt.Errorf("build confidential image: %w", err)
	}

	region := p.Constraints.Region
	opts := VMOptions{
		Name:                   fmt.Sprintf("dispatcher-cs-%s", adapter.SanitizeName(w.Name)),
		Region:                 region,
		ConfidentialType:       "sev-snp",
		ConfidentialSpaceImage: imageRef,
		Tags: map[string]string{
			"dispatcher-run-id": p.Metadata.ID,
			"dispatcher":        "true",
		},
	}
	if d.egressCIDR != nil {
		allowFrom, err := d.egressCIDR(ctx)
		if err != nil {
			return nil, fmt.Errorf("scope confidential agent firewall: %w", err)
		}
		opts.ConfidentialAllowFrom = allowFrom
	}

	dlog.L().Info("cs.create.start", "run", p.Metadata.ID, "image", imageDigest)
	vm, err := d.provider.CreateVM(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("provision confidential space VM: %w", err)
	}

	// Tear the VM down on any error before a verified, completed run. A fresh
	// context so a cancelled run context can't cancel its own cleanup and leak a
	// billing VM.
	destroyOnErr := true
	defer func() {
		if !destroyOnErr {
			return
		}
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Reap the agent-port firewall too — DestroyVM only deletes the instance,
		// so an error after provisioning would otherwise leak the per-run rule
		// (mirrors Cleanup and createConfidentialSpaceVM's own teardown).
		if fw, ok := d.provider.(agentFirewaller); ok {
			_ = fw.deleteAgentFirewall(cctx, agentFirewallName(vm.ID))
		}
		_ = d.provider.DestroyVM(cctx, vm.ID)
	}()

	baseURL := d.baseURL(vm)
	if err := d.waitReady(ctx, baseURL); err != nil {
		return nil, fmt.Errorf("confidential agent endpoint not reachable: %w", err)
	}

	// Verify attestation BEFORE anything is sealed or shipped. The allowlist is
	// exactly the image we just built — the token must attest that digest, echo
	// this run's nonce, and commit to the agent's channel key.
	req := w.Requirements.Confidential
	req.Measurements = []string{imageDigest}
	result, err := csVerify(ctx, d.keys, baseURL, req)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}
	if !result.Verified {
		return nil, fmt.Errorf("attestation rejected: %s", result.Verdict)
	}
	dlog.L().Info("cs.attested", "run", p.Metadata.ID, "vm_id", vm.ID, "digest", result.Measurement)

	// Seal the source + secrets to the attested channel key and run the workload
	// inside the TEE; the result comes back sealed to a fresh dispatcher key.
	runRes, err := runSealedExchange(ctx, baseURL, result.ChannelKey, payload)
	if err != nil {
		return nil, fmt.Errorf("sealed run exchange: %w", err)
	}

	destroyOnErr = false // the run completed; the VM is owned by the run until Cleanup
	return &confidentialRunState{
		Provider:    a2provider(d.provider),
		VMID:        vm.ID,
		Region:      region,
		ImageRef:    imageRef,
		Outputs:     w.Outputs,
		Result:      runRes,
		Attestation: result,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// csVerify is a seam over the CS attester so adapter tests drive the flow
// without a live agent (agent+verify are tested in the attest package).
var csVerify = func(ctx context.Context, keys map[string]crypto.PublicKey, baseURL string, req types.ConfidentialRequirement) (attest.AttestationResult, error) {
	return attest.NewCSAttester(keys, baseURL).Verify(ctx, req)
}

func a2provider(p Provider) ProviderID { return p.Name() }

// buildConfidentialPayload assembles what dispatcher seals to the TEE: the
// workload command, its source (tarred, minus the usual heavy dirs), the .env,
// and the output paths to bring back.
func buildConfidentialPayload(w types.WorkloadSpec) (agent.Payload, error) {
	command, err := csCommand(w)
	if err != nil {
		return agent.Payload{}, err
	}

	entries, err := os.ReadDir(w.Source.Path)
	if err != nil {
		return agent.Payload{}, fmt.Errorf("read source dir: %w", err)
	}
	skip := map[string]bool{".git": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true, ".dispatcher": true}
	var paths []string
	for _, e := range entries {
		if skip[e.Name()] {
			continue
		}
		paths = append(paths, e.Name())
	}
	sourceTar, err := agent.TarGz(w.Source.Path, paths)
	if err != nil {
		return agent.Payload{}, fmt.Errorf("tar source: %w", err)
	}

	// .env is optional; delivered sealed, never over the untrusted channel clear.
	dotenv, err := os.ReadFile(filepath.Join(w.Source.Path, ".env"))
	if err != nil && !os.IsNotExist(err) {
		return agent.Payload{}, fmt.Errorf("read .env: %w", err)
	}

	return agent.Payload{Command: command, SourceTarGz: sourceTar, DotEnv: dotenv, Outputs: w.Outputs}, nil
}

func csCommand(w types.WorkloadSpec) ([]string, error) {
	if len(w.Command) > 0 {
		return w.Command, nil
	}
	if len(w.Entrypoints) > 0 {
		return adapter.RuntimeCommand(w.Runtime, w.Entrypoints[0], false), nil
	}
	return nil, fmt.Errorf("workload has no command or entrypoint")
}

func defaultCSBaseURL(vm *VMInfo) string {
	port := csAgentPort
	if vm.SSHPort > 0 { // reused as the agent port for providers that remap it
		port = vm.SSHPort
	}
	return fmt.Sprintf("http://%s:%d", vm.IP, port)
}

// csAgentPort is the TCP port the in-TEE agent listens on (matches
// dispatcher-attest's default and the provisioned firewall rule).
const csAgentPort = 8443

func (a *ConfidentialSpaceAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	if a.deps.buildImage == nil {
		return nil, fmt.Errorf("confidential space adapter has no image builder configured")
	}
	region := p.Constraints.Region
	if region == "" {
		region = a.config.Region
	}
	if rp, ok := a.deps.provider.(regionalProvider); ok && region != "" {
		rp.SetRegion(region)
	}
	state, err := executeConfidentialSpace(ctx, a.deps, p)
	if err != nil {
		return nil, err
	}
	return &adapter.RunHandle{ID: state.VMID, TargetID: a.targetID, State: state}, nil
}

func (a *ConfidentialSpaceAdapter) Validate(ctx context.Context, _ types.WorkloadSpec) (types.ValidationResult, error) {
	v := types.ValidationResult{
		Schema: types.ValidationPass, PackageBuild: types.ValidationPass,
		TargetCapabilities: types.ValidationPass, Credentials: types.ValidationPass,
		Quota: types.ValidationSkipped, Network: types.ValidationPass,
		Policy: types.ValidationPass, CostEstimate: types.ValidationPass, CleanupPlan: types.ValidationPass,
	}
	if err := a.deps.provider.CheckCLI(ctx); err != nil {
		v.Credentials = types.ValidationFail
		return v, fmt.Errorf("provider CLI check failed: %w", err)
	}
	return v, nil
}

func (a *ConfidentialSpaceAdapter) EstimateCost(_ context.Context, w types.WorkloadSpec) (types.CostEstimate, error) {
	hours := 1.0
	if w.DetectedKind == types.WorkloadKindService {
		hours = 24.0
	}
	total := providerBaseRate(a.config.ProviderID) * hours
	return types.CostEstimate{
		Value: float64(int(total*1000)) / 1000, Currency: "USD", Confidence: types.ConfidenceMedium,
		Assumptions: []string{fmt.Sprintf("assumes %.0fh runtime", hours), "confidential (SEV) VM"},
		Exclusions:  []string{"excludes network egress", "excludes registry storage"},
	}, nil
}

func (a *ConfidentialSpaceAdapter) Prepare(context.Context, *types.Plan) error { return nil }

// Status reports the terminal state captured during Execute — the sealed
// exchange runs synchronously, so a returned handle is always finished.
func (a *ConfidentialSpaceAdapter) Status(_ context.Context, h *adapter.RunHandle) (types.RunState, error) {
	state := h.State.(*confidentialRunState)
	if state.Result.ExitCode != 0 {
		return types.RunStateExecutionFailed, nil
	}
	return types.RunStateCompleted, nil
}

func (a *ConfidentialSpaceAdapter) FailureDetails(h *adapter.RunHandle) adapter.FailureDetails {
	state, ok := h.State.(*confidentialRunState)
	if !ok {
		return adapter.FailureDetails{Message: "no confidential space state"}
	}
	fd := adapter.FailureDetails{ExitCode: state.Result.ExitCode}
	if state.Result.ExitCode != 0 {
		fd.Message = fmt.Sprintf("confidential workload exited with code %d", state.Result.ExitCode)
	}
	return fd
}

// Logs writes the captured (sealed-then-opened) workload output.
func (a *ConfidentialSpaceAdapter) Logs(_ context.Context, h *adapter.RunHandle, w io.Writer) error {
	state := h.State.(*confidentialRunState)
	if len(state.Result.Stdout) > 0 {
		_, _ = w.Write(state.Result.Stdout)
	}
	if len(state.Result.Stderr) > 0 {
		_, _ = w.Write(state.Result.Stderr)
	}
	return nil
}

// Artifacts extracts the sealed outputs tarball into runs/<id>/artifacts/.
func (a *ConfidentialSpaceAdapter) Artifacts(_ context.Context, h *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
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

func (a *ConfidentialSpaceAdapter) Terminate(context.Context, *adapter.RunHandle) error { return nil }

func (a *ConfidentialSpaceAdapter) Cleanup(ctx context.Context, h *adapter.RunHandle) (*adapter.CleanupResult, error) {
	state := h.State.(*confidentialRunState)
	if err := a.deps.provider.DestroyVM(ctx, state.VMID); err != nil {
		return &adapter.CleanupResult{Success: false, Errors: []string{err.Error()}}, nil
	}
	cleaned := []string{state.VMID}
	// Best-effort: reap the per-run agent-port firewall so it doesn't linger.
	if fw, ok := a.deps.provider.(agentFirewaller); ok {
		name := agentFirewallName(state.VMID)
		if err := fw.deleteAgentFirewall(ctx, name); err == nil {
			cleaned = append(cleaned, name)
		}
	}
	return &adapter.CleanupResult{Success: true, ResourcesCleaned: cleaned}, nil
}
