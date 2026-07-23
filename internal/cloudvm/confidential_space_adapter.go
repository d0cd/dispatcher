package cloudvm

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/types"
)

// ConfidentialSpaceAdapter runs a workload on GCP Confidential Space: the
// workload is a measured container, attested by image digest, reached over an
// untrusted TCP channel made safe by an attested TLS session (verify-before-
// deliver; docs/confidential-space-execution.md). It is a distinct execution path
// from the SSH-VM CloudVMAdapter — no SSH, no rsync, no PID; the run is synchronous
// (the aTLS exchange blocks until the workload finishes).
type ConfidentialSpaceAdapter struct {
	// The shared post-run lifecycle (ID/Validate/EstimateCost/Prepare/Status/
	// FailureDetails/Logs/Artifacts/Terminate) is inherited from the base; this
	// adapter overrides only Execute (container path) and Cleanup (also reaps the
	// per-run agent firewall). Its base provider is the same one carried in deps.
	confidentialVMAdapter
	deps csDeps
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
		confidentialVMAdapter: confidentialVMAdapter{
			targetID:       string(cfg.ProviderID) + "-confidential-space",
			provider:       provider,
			config:         cfg,
			costAssumption: "confidential (SEV) VM",
		},
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
	// Enforce the workload's measurement allowlist (if any) against the digest we
	// will attest, before provisioning — a documented control, not a no-op.
	if err := enforceWorkloadMeasurements(w.Requirements.Confidential, imageDigest); err != nil {
		return nil, err
	}

	region := p.Constraints.Region
	opts := VMOptions{
		Name:                   fmt.Sprintf("dispatcher-cs-%s", adapter.SanitizeName(w.Name)),
		Region:                 region,
		ConfidentialType:       "sev-snp",
		ConfidentialSpaceImage: imageRef,
		// Always cap the instance lifetime so a CLI crash that skips the deferred
		// teardown can't leak a billing SEV VM. Use the run's MaxDuration when set,
		// else the watchdog TTL / a default — never 0 (uncapped).
		MaxLifetimeSeconds: int(confidentialLifetime(p.Constraints).Seconds()),
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

	// Attest AND deliver over one attested TLS session (aTLS): the token must
	// attest the image digest we just built, echo this run's nonce, and commit to
	// the TLS session binding — then the workload runs inside the TEE and its result
	// comes back over the same session. Nothing is shipped before verification
	// (RunOverATLS aborts if the peer doesn't verify).
	req := w.Requirements.Confidential
	v := attest.CSValidator(d.keys, []string{imageDigest}, req.Type, req.MinTCB)
	runRes, err := runOverATLS(ctx, strings.TrimPrefix(baseURL, "http://"), v, payload)
	if err != nil {
		return nil, fmt.Errorf("attested aTLS run: %w", err)
	}
	result := v.Result
	dlog.L().Info("cs.attested", "run", p.Metadata.ID, "vm_id", vm.ID, "digest", result.Measurement)

	destroyOnErr = false // the run completed; the VM is owned by the run until Cleanup
	return &confidentialRunState{
		Provider:    d.provider.Name(),
		VMID:        vm.ID,
		Region:      region,
		ImageRef:    imageRef,
		Outputs:     w.Outputs,
		Result:      runRes,
		Attestation: result,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// runOverATLS is a seam over the dispatcher-side aTLS transport so adapter tests
// drive the flow without a live agent (the attested exchange is tested in the
// attest packages).
var runOverATLS = agent.RunOverATLS

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

// confidentialLifetime is the hard instance-lifetime cap for a confidential run:
// the explicit MaxDuration when set, else the watchdog TTL, else the default —
// never 0, which would leave a billing SEV VM uncapped.
func confidentialLifetime(c types.PlanConstraints) time.Duration {
	if c.MaxDuration > 0 {
		return c.MaxDuration
	}
	if c.WatchdogTTL > 0 {
		return c.WatchdogTTL
	}
	return DefaultWatchdogTTL
}
