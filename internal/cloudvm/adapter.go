package cloudvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/dlog"
	statedir "github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/d0cd/dispatcher/internal/workload"
)

// Config holds configuration for creating a CloudVMAdapter.
type Config struct {
	ProviderID ProviderID
	Region     string
	SSHUser    string
}

// CloudVMAdapter implements adapter.TargetAdapter and adapter.DurableAdapter
// for running workloads on cloud VMs.
type CloudVMAdapter struct {
	targetID string
	provider Provider
	config   Config
}

// NewCloudVMAdapter creates an adapter for the given provider.
func NewCloudVMAdapter(provider Provider, cfg Config) *CloudVMAdapter {
	return &CloudVMAdapter{
		targetID: string(cfg.ProviderID) + "-vm",
		provider: provider,
		config:   cfg,
	}
}

func (a *CloudVMAdapter) ID() string { return a.targetID }

// regionalProvider is optionally implemented by providers whose region/zone can
// be re-pointed after construction — from a --region flag on create, or from
// persisted state on reconnect — so create and teardown act on one region.
type regionalProvider interface {
	SetRegion(region string)
}

// applyRegion pins the adapter (and its provider, if regional) to region. A
// no-op for empty region or single-region providers (Hetzner/Lima).
func (a *CloudVMAdapter) applyRegion(region string) {
	if region == "" {
		return
	}
	a.config.Region = region
	if rp, ok := a.provider.(regionalProvider); ok {
		rp.SetRegion(region)
	}
}

func (a *CloudVMAdapter) Validate(ctx context.Context, w types.WorkloadSpec) (types.ValidationResult, error) {
	v := types.ValidationResult{
		Schema:             types.ValidationPass,
		PackageBuild:       types.ValidationPass,
		TargetCapabilities: types.ValidationPass,
		Credentials:        types.ValidationPass,
		Quota:              types.ValidationSkipped,
		Network:            types.ValidationPass,
		Policy:             types.ValidationPass,
		CostEstimate:       types.ValidationPass,
		CleanupPlan:        types.ValidationPass,
	}

	if err := a.provider.CheckCLI(ctx); err != nil {
		v.Credentials = types.ValidationFail
		return v, fmt.Errorf("provider CLI check failed: %w", err)
	}

	return v, nil
}

func (a *CloudVMAdapter) EstimateCost(_ context.Context, w types.WorkloadSpec) (types.CostEstimate, error) {
	// Use a generic estimate based on provider — the catalog will refine this
	hours := 1.0
	if w.DetectedKind == types.WorkloadKindService {
		hours = 24.0
	}

	rate := providerBaseRate(a.config.ProviderID)
	total := rate * hours
	total = float64(int(total*1000)) / 1000 // round to 3 decimal places

	assumptions := []string{fmt.Sprintf("assumes %.0fh runtime", hours)}
	if w.DetectedKind == types.WorkloadKindService {
		assumptions = []string{"assumes 24h runtime for service"}
	}

	return types.CostEstimate{
		Value:       total,
		Currency:    "USD",
		Confidence:  types.ConfidenceMedium,
		Assumptions: assumptions,
		Exclusions:  []string{"excludes network egress", "excludes storage"},
	}, nil
}

func (a *CloudVMAdapter) Prepare(ctx context.Context, p *types.Plan) error {
	return nil // VM creation happens in Execute
}

// buildVMOptions assembles the provisioning request for a plan. InstanceType
// comes from the recommended target's priced estimate, so the VM that launches
// matches the one that was costed; an empty value (non-catalog estimate) lets
// the provider fall back to its default instance.
func buildVMOptions(p *types.Plan, region, vmName, pubKeyPath, userData string) VMOptions {
	var instanceType string
	if p.Recommendation != nil {
		instanceType = p.Recommendation.EstimatedCost.InstanceType
	}
	opts := VMOptions{
		Name:         vmName,
		Region:       region,
		InstanceType: instanceType,
		SSHKeyPath:   pubKeyPath,
		UserData:     userData,
		AllowSSHFrom: p.Constraints.AllowSSHFrom,
		Spot:         p.Constraints.Spot,
		Tags: map[string]string{
			"dispatcher-run-id": p.Metadata.ID,
			"dispatcher":        "true",
		},
	}
	if c := p.Workload.Requirements.Confidential; c.Required {
		opts.ConfidentialType = c.Type
		if opts.ConfidentialType == "" {
			opts.ConfidentialType = "any"
		}
	}
	return opts
}

// validateGPUInstance refuses to provision when a workload requires a GPU but no
// specific instance type was resolved — otherwise the provider would silently
// launch its CPU-only default (e.g. an unpinned or unrecognized gpu.model that
// matched nothing in the catalog).
func validateGPUInstance(w types.WorkloadSpec, instanceType string) error {
	if w.Requirements.GPU.Required && instanceType == "" {
		return fmt.Errorf("workload requires a GPU but no catalog instance matched; " +
			"pin a supported gpu.model or choose a provider with GPU inventory — " +
			"refusing to provision a CPU-only instance")
	}
	return nil
}

func (a *CloudVMAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	w := p.Workload

	keyPath, err := generateSSHKey(ctx, p.Metadata.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH key: %w", err)
	}

	// earlyCleanup runs on any error return; cleared after success so
	// Cleanup() owns deletion instead.
	earlyCleanup := []string{keyPath, keyPath + ".pub"}
	defer func() {
		if earlyCleanup == nil {
			return
		}
		for _, p := range earlyCleanup {
			_ = os.Remove(p)
		}
	}()

	sshUser := a.config.SSHUser
	if sshUser == "" {
		sshUser = "root"
	}
	remoteDir := "/tmp/dispatcher/" + p.Metadata.ID

	// Watchdog TTL — lower shrinks the worst-case bill when dispatcher
	// dies; higher buys more reconnect grace.
	ttl := DefaultWatchdogTTL
	if p.Constraints.WatchdogTTL > 0 {
		ttl = p.Constraints.WatchdogTTL
	}
	userData := WatchdogCloudInit(ttl, sshUser)
	vmName := fmt.Sprintf("dispatcher-%s", adapter.SanitizeName(w.Name))

	// Pin the region: the plan's choice wins over the adapter default, and the
	// provider is re-pointed so teardown later hits the same region.
	region := p.Constraints.Region
	if region == "" {
		region = a.config.Region
	}
	a.applyRegion(region)

	opts := buildVMOptions(p, a.config.Region, vmName, keyPath+".pub", userData)
	opts.SSHUser = sshUser // the provider must authorize the key for this login
	if err := validateGPUInstance(w, opts.InstanceType); err != nil {
		return nil, err
	}
	if err := confidentialAttestationPreflight(w, a.config.ProviderID); err != nil {
		return nil, err
	}

	dlog.L().Info("cloudvm.create.start",
		"run", p.Metadata.ID, "provider", string(a.config.ProviderID),
		"name", opts.Name, "region", opts.Region, "ttl", ttl.String())
	vmInfo, err := a.provider.CreateVM(ctx, opts)
	if err != nil {
		dlog.L().Error("cloudvm.create.failed",
			"run", p.Metadata.ID, "provider", string(a.config.ProviderID), "err", err.Error())
		return nil, fmt.Errorf("VM creation failed: %w", err)
	}
	dlog.L().Info("cloudvm.create.ok",
		"run", p.Metadata.ID, "vm_id", vmInfo.ID, "ip", vmInfo.IP)

	// Destroy the VM if Execute returns an error after creating it. A fresh
	// context is essential: if the run context was cancelled (e.g. Ctrl-C during
	// provisioning), reusing it would cancel the teardown too and leak a billing
	// VM. Cleared on success so Cleanup owns the VM.
	destroyOnErr := true
	defer func() {
		if !destroyOnErr {
			return
		}
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = a.provider.DestroyVM(cctx, vmInfo.ID)
	}()

	// Wait for SSH
	if err := a.provider.WaitReady(ctx, vmInfo.ID, vmInfo.IP, keyPath); err != nil {
		dlog.L().Error("cloudvm.ssh_wait.failed",
			"run", p.Metadata.ID, "vm_id", vmInfo.ID, "err", err.Error())
		return nil, fmt.Errorf("VM not reachable via SSH: %w", err)
	}
	dlog.L().Info("cloudvm.ssh_ready", "run", p.Metadata.ID, "vm_id", vmInfo.ID)

	sshPort := 22
	if vmInfo.SSHPort > 0 {
		sshPort = vmInfo.SSHPort
	}

	// Lima supplies its own SSH identity (host user's key); cloud
	// providers use the per-run generated key. When the provider
	// overrides, drop the unused key and mark Cleanup hands-off.
	effectiveKey := keyPath
	keyManaged := true
	if vmInfo.SSHKeyPath != "" {
		_ = os.Remove(keyPath)
		_ = os.Remove(keyPath + ".pub")
		earlyCleanup = nil
		effectiveKey = vmInfo.SSHKeyPath
		keyManaged = false
	}

	effectiveUser := sshUser
	if vmInfo.SSHUser != "" {
		effectiveUser = vmInfo.SSHUser // provider knows its image's default
	}

	state := &CloudVMState{
		Provider:      a.config.ProviderID,
		VMID:          vmInfo.ID,
		IP:            vmInfo.IP,
		SSHKeyPath:    effectiveKey,
		SSHKeyManaged: keyManaged,
		SSHUser:       effectiveUser,
		SSHPort:       sshPort,
		Region:        a.config.Region,
		InstanceType:  opts.InstanceType,
		RemoteDir:     remoteDir,
		LogPath:       remoteDir + "/dispatcher.log",
		CreatedAt:     time.Now().UTC(),
		Outputs:       w.Outputs,
		Spot:          opts.Spot,
	}

	// Pin host key now so subsequent SSH/rsync use StrictHostKeyChecking=yes,
	// shrinking the MITM window to first-contact.
	if err := PinHostKey(ctx, state, p.Metadata.ID); err != nil {
		dlog.L().Error("cloudvm.keypin.failed",
			"run", p.Metadata.ID, "vm_id", vmInfo.ID, "err", err.Error())
		return nil, fmt.Errorf("pin host key: %w", err)
	}
	earlyCleanup = append(earlyCleanup, state.KnownHostsPath)
	dlog.L().Info("cloudvm.keypin.ok",
		"run", p.Metadata.ID, "vm_id", vmInfo.ID, "known_hosts", state.KnownHostsPath)

	// TCP-readiness can precede the boot-time (user-data) key install on AWS,
	// so confirm the key is actually accepted before rsync — otherwise the
	// first transfer fails with a publickey error.
	if err := WaitForSSHAuth(ctx, state, 2*time.Minute); err != nil {
		return nil, fmt.Errorf("wait for authenticated ssh: %w", err)
	}

	wrapper, err := writeSSHWrapper(state, p.Metadata.ID)
	if err != nil {
		return nil, fmt.Errorf("build ssh wrapper: %w", err)
	}
	state.SSHWrapper = wrapper
	earlyCleanup = append(earlyCleanup, wrapper)

	// Verify TEE attestation before running anything on a confidential VM. A
	// rejection or error returns here, and the destroyOnErr defer tears the VM
	// down — we never run a workload on a VM we couldn't prove.
	if att, err := verifyConfidential(ctx, a.config.ProviderID, vmInfo, effectiveKey, effectiveUser, w.Requirements.Confidential); err != nil {
		return nil, err
	} else if att != nil {
		state.Attestation = att
		if att.Verified {
			dlog.L().Info("cloudvm.attested", "run", p.Metadata.ID, "vm_id", vmInfo.ID, "type", att.Type)
		} else {
			dlog.L().Warn("cloudvm.attestation_unverified", "run", p.Metadata.ID, "vm_id", vmInfo.ID, "verdict", att.Verdict)
		}
	}

	// cloud-init restarts sshd during its "final" phase; wait for it to
	// avoid mid-flight exit-255 failures. No-op on images without cloud-init.
	if err := waitForCloudInit(ctx, state); err != nil {
		dlog.L().Warn("cloudvm.cloudinit_wait_failed",
			"run", p.Metadata.ID, "vm_id", vmInfo.ID, "err", err.Error())
		// Non-fatal; downstream retries cover it.
	} else {
		dlog.L().Info("cloudvm.cloudinit_done", "run", p.Metadata.ID, "vm_id", vmInfo.ID)
	}

	// Execute does not return a durable handle until source upload and workload
	// startup finish. The normal executor heartbeat cannot renew the VM watchdog
	// before then, so a large rsync can outlive the TTL and make a correctly
	// supervised VM shut itself down mid-transfer. Maintain the lease during
	// this setup window, then hand renewal back to the executor with the handle.
	stopSetupWatchdog := maintainSetupWatchdog(ctx, state, ttl)
	defer stopSetupWatchdog()

	// Rsync source to VM
	if err := rsyncToVM(ctx, state, w.Source.Path); err != nil {
		dlog.L().Error("cloudvm.rsync.failed",
			"run", p.Metadata.ID, "vm_id", vmInfo.ID, "err", err.Error())
		return nil, fmt.Errorf("rsync failed: %w", err)
	}
	dlog.L().Info("cloudvm.rsync.ok", "run", p.Metadata.ID, "vm_id", vmInfo.ID)

	// Start workload
	if err := startWorkloadOnVM(ctx, state, w); err != nil {
		dlog.L().Error("cloudvm.workload_start.failed",
			"run", p.Metadata.ID, "vm_id", vmInfo.ID, "err", err.Error())
		return nil, fmt.Errorf("workload start failed: %w", err)
	}
	dlog.L().Info("cloudvm.workload_start.ok",
		"run", p.Metadata.ID, "vm_id", vmInfo.ID, "pid", state.WorkloadPID)

	earlyCleanup = nil   // success — Cleanup owns the files now
	destroyOnErr = false // success — the VM is live and owned by the run

	return &adapter.RunHandle{
		ID:       vmInfo.ID,
		TargetID: a.targetID,
		State:    state,
	}, nil
}

func maintainSetupWatchdog(ctx context.Context, state *CloudVMState, ttl time.Duration) context.CancelFunc {
	renewCtx, cancel := context.WithCancel(ctx)
	interval := setupWatchdogInterval(ttl)
	go func() {
		// Renew immediately so the setup phase gets a full TTL rather than the
		// remainder of the boot-time lease.
		if _, err := ExtendWatchdogViaSSH(renewCtx, state, ttl); err != nil && renewCtx.Err() == nil {
			dlog.L().Warn("cloudvm.setup_watchdog_renew_failed", "vm_id", state.VMID, "err", err.Error())
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-ticker.C:
				if _, err := ExtendWatchdogViaSSH(renewCtx, state, ttl); err != nil && renewCtx.Err() == nil {
					dlog.L().Warn("cloudvm.setup_watchdog_renew_failed", "vm_id", state.VMID, "err", err.Error())
				}
			}
		}
	}()
	return cancel
}

func setupWatchdogInterval(ttl time.Duration) time.Duration {
	interval := ttl / 3
	if interval < time.Second {
		interval = time.Second
	}
	return interval
}

func (a *CloudVMAdapter) Status(ctx context.Context, h *adapter.RunHandle) (types.RunState, error) {
	state := h.State.(*CloudVMState)

	// Check if VM still exists
	vmInfo, err := a.provider.GetVM(ctx, state.VMID)
	if err != nil {
		return types.RunStateExecutionFailed, fmt.Errorf("cannot get VM status: %w", err)
	}

	if vmInfo.State == VMStateTerminated {
		// A spot/preemptible VM that vanishes mid-run was reclaimed by the
		// provider, not by dispatcher. Record it so FailureDetails classifies the
		// failure as transient and --retry-transient re-provisions.
		if state.Spot {
			state.Reclaimed = true
		}
		return types.RunStateExecutionFailed, nil
	}

	// Check if workload process is still running
	if state.WorkloadPID > 0 {
		checkCmd := fmt.Sprintf("kill -0 %d 2>/dev/null && echo running || echo done", state.WorkloadPID)
		args := sshCmdArgs(state, checkCmd)
		output, err := exec.CommandContext(ctx, "ssh", args...).Output()
		if err != nil {
			// The provider proves that the VM exists, but only SSH can prove that
			// dispatcher's in-guest supervisor remains observable. Surface loss of
			// that channel as an indeterminate Status error. The executor tolerates
			// a bounded number of consecutive errors, preventing both a one-blip
			// teardown and an unlimited, permanently unobservable billing loop.
			return types.RunStateRunning, fmt.Errorf("ssh liveness probe failed: %w", err)
		}
		if strings.TrimSpace(string(output)) == "done" {
			// Read the exit-code file the runner script wrote; without it
			// every workload would report "Completed" regardless of outcome.
			readCmd := fmt.Sprintf("cat %s 2>/dev/null", adapter.ShellQuote(remoteExitCodePath(state)))
			readArgs := sshCmdArgs(state, readCmd)
			out, _ := exec.CommandContext(ctx, "ssh", readArgs...).Output()
			codeStr := strings.TrimSpace(string(out))
			if codeStr == "" {
				// No exit-code file = workload killed before runner could
				// record (OOM, external SIGKILL). -1 sentinel.
				state.LastExitCode = -1
				state.LastExitCodeRead = false
				return types.RunStateExecutionFailed, nil
			}
			code := 0
			fmt.Sscanf(codeStr, "%d", &code)
			state.LastExitCode = code
			state.LastExitCodeRead = true
			if code != 0 {
				return types.RunStateExecutionFailed, nil
			}
			return types.RunStateCompleted, nil
		}
	}

	return types.RunStateRunning, nil
}

// FailureDetails returns the workload's exit code from the runner script's
// exit-code file. Missing file = SIGKILL-equivalent (OOM / external kill).
func (a *CloudVMAdapter) FailureDetails(h *adapter.RunHandle) adapter.FailureDetails {
	state, ok := h.State.(*CloudVMState)
	if !ok {
		return adapter.FailureDetails{Message: "no cloud vm state"}
	}
	// A reclaimed spot VM is gone — SSH evidence capture would only time out.
	// Report the reclaim directly; it classifies transient.
	if state.Reclaimed {
		return adapter.FailureDetails{
			Reclaimed: true,
			Message:   fmt.Sprintf("spot instance reclaimed by the provider (%s VM %s)", state.Provider, state.VMID),
		}
	}
	// Capture kernel/cgroup OOM evidence from the still-alive VM before teardown,
	// so diagnose can state OOM as a fact rather than a guess.
	ev := captureFailureEvidence(state)

	if !state.LastExitCodeRead {
		fd := adapter.FailureDetails{
			Signal:  "SIGKILL",
			Message: "workload terminated before exit code was captured (likely OOM or external kill)",
		}
		if ev.oomKilled {
			fd.OOMKilled = true
			fd.Message = "workload OOM-killed: " + ev.summary
		}
		return fd
	}
	fd := adapter.FailureDetails{ExitCode: state.LastExitCode}
	if state.LastExitCode != 0 {
		fd.Message = fmt.Sprintf("workload exited with code %d on %s VM %s",
			state.LastExitCode, state.Provider, state.VMID)
	}
	// Kernel evidence turns a 137/SIGKILL guess into a confirmed OOM.
	if ev.oomKilled {
		fd.OOMKilled = true
		fd.Message = "workload OOM-killed: " + ev.summary + " (" + fd.Message + ")"
	}
	return fd
}

// failureEvidence is the OOM verdict captureFailureEvidence extracts from a
// failed VM's kernel log / cgroup before teardown.
type failureEvidence struct {
	oomKilled bool
	summary   string // bounded, human-readable
}

// maxEvidenceSummary bounds the captured evidence line kept on the run record —
// kernel lines can be long and workload-private detail shouldn't accumulate.
const maxEvidenceSummary = 200

// captureFailureEvidence best-effort SSHes the still-alive VM for OOM evidence:
// the kernel OOM-killer lines and the cgroup oom_kill counter. Empty when the VM
// is unreachable (already torn down / network gone) — absence is not evidence.
func captureFailureEvidence(state *CloudVMState) failureEvidence {
	// dmesg is root-restricted on stock images; try sudo then fall back. The
	// cgroup memory.events oom_kill counter is world-readable.
	cmd := "{ sudo -n dmesg 2>/dev/null || dmesg 2>/dev/null; } | grep -iE 'out of memory|oom-kill|killed process' | tail -5; " +
		"cat /sys/fs/cgroup/memory.events 2>/dev/null | grep -E '^oom_kill '"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Parse whatever stdout we get even on a non-zero exit: the trailing cgroup
	// grep exits 1 when it finds nothing, which would otherwise discard a dmesg
	// OOM line already on stdout. A total SSH failure just yields "" (not OOM).
	out, _ := exec.CommandContext(ctx, "ssh", sshCmdArgs(state, cmd)...).Output()
	return parseOOMEvidence(string(out))
}

// parseOOMEvidence classifies captured kernel/cgroup output. OOM is confirmed
// only by a kernel OOM-killer line or a non-zero cgroup oom_kill counter;
// otherwise the verdict is "not confirmed" (uncertainty preserved).
func parseOOMEvidence(raw string) failureEvidence {
	oom := false
	summary := ""
	for _, line := range strings.Split(raw, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "out of memory") || strings.Contains(lower, "oom-kill") || strings.Contains(lower, "killed process") {
			oom = true
			if summary == "" {
				summary = strings.TrimSpace(line)
			}
		}
		if f := strings.Fields(line); len(f) == 2 && f[0] == "oom_kill" && f[1] != "0" {
			oom = true
		}
	}
	if !oom {
		return failureEvidence{}
	}
	if summary == "" {
		summary = "cgroup oom_kill counter is non-zero"
	}
	if len(summary) > maxEvidenceSummary {
		summary = summary[:maxEvidenceSummary] + "…"
	}
	return failureEvidence{oomKilled: true, summary: summary}
}

// Logs spawns `ssh ... tail -f` in a goroutine and returns immediately so
// the executor can proceed to Status polling. The tail process dies with
// the SSH connection (typically at VM destroy time).
func (a *CloudVMAdapter) Logs(ctx context.Context, h *adapter.RunHandle, w io.Writer) error {
	state := h.State.(*CloudVMState)
	tailCmd := fmt.Sprintf("tail -f %s 2>/dev/null", state.LogPath)
	args := sshCmdArgs(state, tailCmd)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start log tail: %w", err)
	}
	go func() { _ = cmd.Wait() }() // exit on ctx cancel / VM destroy is expected
	return nil
}

// Artifacts rsyncs state.Outputs from the VM into runs/<run-id>/artifacts/.
// Called on both success and failure (crash dumps are the whole point).
// Retrieval errors are reported but non-fatal so cleanup still runs.
func (a *CloudVMAdapter) Artifacts(ctx context.Context, h *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
	state := h.State.(*CloudVMState)
	if len(state.Outputs) == 0 {
		return nil, nil
	}

	indexKey := h.RunID
	if indexKey == "" {
		indexKey = h.ID // legacy handles index by VM id
	}
	dest, err := statedir.Subdir(filepath.Join("runs", indexKey, "artifacts"))
	if err != nil {
		return nil, fmt.Errorf("create artifacts dir: %w", err)
	}

	rootAbs, err := filepath.Abs(dest)
	if err != nil {
		return nil, fmt.Errorf("resolve artifacts dir: %w", err)
	}

	var refs []adapter.ArtifactRef
	var firstErr error
	for _, out := range state.Outputs {
		// Defense in depth — sanitizeOutputs at config load is the
		// primary gate; this catches hand-built state.
		if filepath.IsAbs(out) || strings.Contains(out, "..") {
			if firstErr == nil {
				firstErr = fmt.Errorf("rejected output path %q (absolute or traversal)", out)
			}
			continue
		}
		// Preserve trailing-slash semantics (rsync: contents-of vs the-dir).
		remoteSrc := fmt.Sprintf("%s@%s:%s/%s", state.SSHUser, state.IP, state.RemoteDir, out)
		localDest := filepath.Join(dest, filepath.Clean(out))
		destAbs, err := filepath.Abs(localDest)
		if err != nil || !strings.HasPrefix(destAbs+string(filepath.Separator), rootAbs+string(filepath.Separator)) {
			if firstErr == nil {
				firstErr = fmt.Errorf("output %q escapes artifacts root", out)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(localDest), 0o700); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("mkdir %s: %w", filepath.Dir(localDest), err)
			}
			continue
		}

		// `--safe-links` blocks rsync from following symlinks that point
		// outside the transferred tree (defense against a workload planting
		// a symlink to /etc/shadow in outputs/). `--protect-args` disables
		// remote-shell parsing of the path so rsync ships the source string
		// to the remote rsync without re-tokenization — defense in depth
		// against malicious workload-supplied output paths.
		eArg, err := sshWrapperArg(state)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		cmd := exec.CommandContext(ctx, "rsync",
			"-az", "--safe-links", "--protect-args",
			"-e", eArg, remoteSrc, localDest)
		if err := cmd.Run(); err != nil {
			// rsync exit 23 = partial transfer: a declared but optional output the
			// workload didn't produce. That's not a failure — skip it without
			// recording an error; any other exit code is a real transfer failure.
			if rsyncExitCode(err) == 23 {
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("rsync %s: %w", out, err)
			}
			continue
		}

		_ = filepath.Walk(localDest, func(p string, info os.FileInfo, _ error) error {
			if info == nil || info.IsDir() {
				return nil
			}
			refs = append(refs, adapter.ArtifactRef{
				Name: filepath.Base(p),
				Path: p,
				Size: info.Size(),
			})
			return nil
		})
	}

	return refs, firstErr
}

// rsyncExitCode returns the process exit code from a failed rsync exec, or -1 if
// the error isn't a process exit (e.g. rsync not found, context cancelled).
func rsyncExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func (a *CloudVMAdapter) Terminate(ctx context.Context, h *adapter.RunHandle) error {
	state := h.State.(*CloudVMState)
	if state.WorkloadPID > 0 {
		killCmd := fmt.Sprintf("kill %d 2>/dev/null || true", state.WorkloadPID)
		args := sshCmdArgs(state, killCmd)
		_ = exec.CommandContext(ctx, "ssh", args...).Run()
	}
	return nil
}

func (a *CloudVMAdapter) Cleanup(ctx context.Context, h *adapter.RunHandle) (*adapter.CleanupResult, error) {
	state := h.State.(*CloudVMState)

	dlog.L().Info("cloudvm.destroy.start",
		"run", h.ID, "vm_id", state.VMID, "provider", string(state.Provider))
	if err := a.provider.DestroyVM(ctx, state.VMID); err != nil {
		dlog.L().Error("cloudvm.destroy.failed",
			"run", h.ID, "vm_id", state.VMID, "err", err.Error())
		return &adapter.CleanupResult{
			Success: false,
			Errors:  []string{err.Error()},
		}, nil
	}
	dlog.L().Info("cloudvm.destroy.ok", "run", h.ID, "vm_id", state.VMID)

	// Remove only our own ephemeral key. Provider-supplied identities
	// (Lima's ~/.lima/_config/user) are shared and managed by the provider.
	if state.SSHKeyManaged {
		_ = os.Remove(state.SSHKeyPath)
		_ = os.Remove(state.SSHKeyPath + ".pub")
	}
	if state.KnownHostsPath != "" {
		_ = os.Remove(state.KnownHostsPath)
	}
	if state.SSHWrapper != "" {
		_ = os.Remove(state.SSHWrapper)
	}

	return &adapter.CleanupResult{
		Success:          true,
		ResourcesCleaned: []string{state.VMID},
	}, nil
}

// DurableAdapter methods

func (a *CloudVMAdapter) Reconnect(_ context.Context, handleID string, raw json.RawMessage) (*adapter.RunHandle, error) {
	state, err := UnmarshalCloudVMState(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize handle state: %w", err)
	}

	// Re-point the freshly-constructed provider at the VM's region so status
	// checks and teardown after a CLI restart hit where the VM actually lives.
	a.applyRegion(state.Region)

	return &adapter.RunHandle{
		ID:       handleID,
		TargetID: a.targetID,
		State:    state,
	}, nil
}

func (a *CloudVMAdapter) ExtendWatchdog(ctx context.Context, h *adapter.RunHandle, ttl time.Duration) (time.Time, error) {
	state := h.State.(*CloudVMState)
	return ExtendWatchdogViaSSH(ctx, state, ttl)
}

// resourceEnumerator is an optional Provider capability: enumerate ALL
// dispatcher-tagged billable resources (beyond instances — disks/images/
// snapshots/addresses/firewalls) and destroy them by kind. Providers implement
// it incrementally; the adapter falls back to ListVMs/DestroyVM otherwise.
type resourceEnumerator interface {
	ListResources(ctx context.Context) ([]adapter.ResourceInfo, error)
	DestroyResource(ctx context.Context, res adapter.ResourceInfo) error
}

func (a *CloudVMAdapter) ListResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	if re, ok := a.provider.(resourceEnumerator); ok {
		return re.ListResources(ctx)
	}
	// Fallback: instances only. VMInfo doesn't carry the instance type, so cost
	// is left to the per-provider enumerator (Phase 2); an orphaned running
	// instance is reaped regardless.
	vms, err := a.provider.ListVMs(ctx, map[string]string{"dispatcher": "true"})
	if err != nil {
		return nil, err
	}
	var resources []adapter.ResourceInfo
	for _, vm := range vms {
		resources = append(resources, adapter.ResourceInfo{
			ResourceID: vm.ID,
			Provider:   string(a.config.ProviderID),
			Kind:       adapter.ResourceInstance,
			CreatedAt:  vm.CreatedAt,
			RunID:      vm.Tags["dispatcher-run-id"],
			Tags:       vm.Tags,
		})
	}
	return resources, nil
}

func (a *CloudVMAdapter) DestroyResource(ctx context.Context, res adapter.ResourceInfo) error {
	// Hard ownership boundary: never modify a resource dispatcher doesn't own.
	if !res.DispatcherOwned() {
		return fmt.Errorf("refusing to destroy %s %q: not dispatcher-owned", res.Kind, res.ResourceID)
	}
	if re, ok := a.provider.(resourceEnumerator); ok {
		return re.DestroyResource(ctx, res)
	}
	// Fallback providers only know how to destroy instances.
	if res.Kind != "" && res.Kind != adapter.ResourceInstance {
		return fmt.Errorf("provider %s cannot destroy %s resources yet", a.config.ProviderID, res.Kind)
	}
	return a.provider.DestroyVM(ctx, res.ResourceID)
}

// --- helpers ---

func providerBaseRate(p ProviderID) float64 {
	switch p {
	case ProviderHetzner:
		return 0.007 // cx22 ~€0.006/hr
	case ProviderAWS:
		return 0.05 // t3.micro ~$0.01, t3.medium ~$0.04
	case ProviderGCP:
		return 0.04 // e2-medium ~$0.03
	case ProviderAzure:
		return 0.05 // B2s ~$0.04
	case ProviderLambda:
		return 0.75 // GPU cloud: gpu_1x_a100 ~$1.29/hr, gpu_1x_gh200 ~$1.49; floor low
	default:
		return 0.10
	}
}

// RemoveRunKeyFiles deletes the per-run SSH artifacts a cloud-VM run leaves in
// the state keys dir (private key, .pub, known_hosts, ssh wrapper). gc uses it
// to reclaim key material when reaping an orphaned VM, since the normal Cleanup
// path never ran. Best-effort: missing files are ignored.
func RemoveRunKeyFiles(runID string) {
	// runID can come from a cloud VM tag; a separator or traversal in it would
	// let os.Remove escape the keys dir, so refuse anything path-unsafe.
	if strings.ContainsAny(runID, "/\\") || strings.Contains(runID, "..") {
		return
	}
	keyDir, err := statedir.Subdir("keys")
	if err != nil {
		return
	}
	for _, name := range []string{
		"dispatcher-" + runID,
		"dispatcher-" + runID + ".pub",
		"known_hosts-" + runID,
		"ssh-wrapper-" + runID + ".sh",
	} {
		_ = os.Remove(filepath.Join(keyDir, name))
	}
}

func generateSSHKey(ctx context.Context, runID string) (string, error) {
	keyDir, err := statedir.Subdir("keys")
	if err != nil {
		return "", err
	}
	keyPath := filepath.Join(keyDir, "dispatcher-"+runID)

	// ssh-keygen with a bounded context — under load it can hang briefly,
	// and we'd rather propagate cancellation than block the executor forever.
	keygenCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(keygenCtx, "ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-q")
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh-keygen failed: %w", err)
	}

	return keyPath, nil
}

// waitForCloudInit blocks until cloud-init's final phase finishes so
// we don't race its sshd reconfig. No-op without cloud-init.
func waitForCloudInit(ctx context.Context, state *CloudVMState) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := "command -v cloud-init >/dev/null 2>&1 && cloud-init status --wait >/dev/null 2>&1 || true"
	return sshRunWithRetry(waitCtx, state, cmd, 6, 5*time.Second)
}

// sshRunWithRetry retries on SSH transport errors (exit 255). Used to
// ride out the sshd-restart window during cloud-init.
func sshRunWithRetry(ctx context.Context, state *CloudVMState, remoteCmd string, attempts int, backoff time.Duration) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		args := sshCmdArgs(state, remoteCmd)
		err := exec.CommandContext(ctx, "ssh", args...).Run()
		if err == nil {
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return lastErr
}

func rsyncToVM(ctx context.Context, state *CloudVMState, sourcePath string) error {
	mkdirCmd := fmt.Sprintf("mkdir -p %s", adapter.ShellQuote(state.RemoteDir))
	if err := sshRunWithRetry(ctx, state, mkdirCmd, 5, 5*time.Second); err != nil {
		return fmt.Errorf("mkdir failed: %w", err)
	}

	dest := fmt.Sprintf("%s@%s:%s/", state.SSHUser, state.IP, state.RemoteDir)
	rsyncArgs, err := rsyncUploadArgs(state, sourcePath, dest)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		cmd := exec.CommandContext(ctx, "rsync", rsyncArgs...)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err == nil {
			return nil
		} else {
			lastErr = err
			if rsyncExitCode(err) != 255 || attempt == 4 {
				break
			}
			fmt.Fprintf(os.Stderr, "rsync transport interrupted; resuming partial transfer (attempt %d/4)\n", attempt+1)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 5 * time.Second):
		}
	}
	return fmt.Errorf("rsync failed: %w", lastErr)
}

func rsyncUploadArgs(state *CloudVMState, sourcePath, dest string) ([]string, error) {
	eArg, err := sshWrapperArg(state)
	if err != nil {
		return nil, err
	}
	args := []string{
		"-az", "--delete", "--progress", "--protect-args",
		"--partial", "--append-verify", "-e", eArg,
	}
	for _, ex := range []string{".git", "node_modules", ".venv", "venv", "__pycache__", ".dispatcher"} {
		args = append(args, "--exclude", ex)
	}
	// .dispatchignore patterns starting with `-` would be parsed by rsync
	// as flags (--include, --delete-after, ...) — option injection.
	patterns, _ := workload.LoadIgnorePatterns(sourcePath)
	for _, p := range patterns {
		if strings.HasPrefix(p, "-") {
			fmt.Fprintf(os.Stderr, "warning: ignoring .dispatchignore pattern %q (starts with -)\n", p)
			continue
		}
		args = append(args, "--exclude", p)
	}
	return append(args, sourcePath+"/", dest), nil
}

// controlPlaneNiceness lowers the workload's CPU scheduling priority so a
// CPU-saturating job can't starve dispatcher's on-VM control plane — sshd, the
// watchdog-renewal SSH, and log streaming — which otherwise surfaces as SSH
// timeouts mid-run. The workload author does nothing; the nicer priority only
// yields CPU when the box is contended, so throughput is unaffected when idle.
const controlPlaneNiceness = 10

// niceCommand wraps a workload command so it runs at lower CPU priority, leaving
// headroom for the control plane. `nice` is coreutils (present on every image)
// and propagates the wrapped command's exit code.
func niceCommand(cmdStr string) string {
	return fmt.Sprintf("nice -n %d %s", controlPlaneNiceness, cmdStr)
}

func startWorkloadOnVM(ctx context.Context, state *CloudVMState, w types.WorkloadSpec) error {
	var cmdStr string
	if len(w.Command) > 0 {
		cmdStr = adapter.ShellQuoteArgs(w.Command)
	} else if len(w.Entrypoints) > 0 {
		parts := adapter.RuntimeCommand(w.Runtime, w.Entrypoints[0], false)
		cmdStr = adapter.ShellQuoteArgs(parts)
	} else {
		return fmt.Errorf("no command or entrypoint for remote execution")
	}

	envExports, err := adapter.DotEnvExportScript(w.Source.Path, w.Env)
	if err != nil {
		return err
	}

	// Two-step: stream runner script via SSH stdin (no shell-quoting hell),
	// then nohup it. The runner records the exit code for FailureDetails.
	exitCodePath := state.RemoteDir + "/dispatcher.exitcode"
	runnerPath := state.RemoteDir + "/dispatcher-runner.sh"
	logPath := state.LogPath

	runnerScript := envExports + fmt.Sprintf(
		"cd %s\n"+
			"{\n"+
			"  %s\n"+
			"} > %s 2>&1\n"+
			"echo $? > %s\n",
		adapter.ShellQuote(state.RemoteDir),
		niceCommand(cmdStr),
		adapter.ShellQuote(logPath),
		adapter.ShellQuote(exitCodePath),
	)

	// Stream over stdin so the script never enters argv. Retries cover
	// the exit-255 window when cloud-init reconfigures sshd post-first-SSH.
	writeCmd := fmt.Sprintf("cat > %s && chmod +x %s",
		adapter.ShellQuote(runnerPath), adapter.ShellQuote(runnerPath))
	writeArgs := sshCmdArgs(state, writeCmd)
	var writeErr error
	for attempt := 0; attempt < 5; attempt++ {
		writeProc := exec.CommandContext(ctx, "ssh", writeArgs...)
		writeProc.Stdin = strings.NewReader(runnerScript)
		writeErr = writeProc.Run()
		if writeErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("install runner cancelled: %w", ctx.Err())
		case <-time.After(time.Duration(5*(attempt+1)) * time.Second):
		}
	}
	if writeErr != nil {
		return fmt.Errorf("install runner (after 5 attempts): %w", writeErr)
	}

	launchCmd := fmt.Sprintf("nohup %s > /dev/null 2>&1 & echo $!", adapter.ShellQuote(runnerPath))
	launchArgs := sshCmdArgs(state, launchCmd)
	output, err := exec.CommandContext(ctx, "ssh", launchArgs...).Output()
	if err != nil {
		return fmt.Errorf("start failed: %w", err)
	}

	pidStr := strings.TrimSpace(string(output))
	var pid int
	fmt.Sscanf(pidStr, "%d", &pid)
	state.WorkloadPID = pid

	return nil
}

func remoteExitCodePath(state *CloudVMState) string {
	return state.RemoteDir + "/dispatcher.exitcode"
}
