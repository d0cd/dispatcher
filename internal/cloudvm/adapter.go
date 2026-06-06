package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
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

func (a *CloudVMAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	w := p.Workload

	// Generate ephemeral SSH key
	keyPath, err := generateSSHKey(p.Metadata.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH key: %w", err)
	}

	sshUser := a.config.SSHUser
	if sshUser == "" {
		sshUser = "root"
	}
	remoteDir := "/tmp/dispatcher/" + p.Metadata.ID

	// Create VM with watchdog
	userData := WatchdogCloudInit(DefaultWatchdogTTL)
	vmName := fmt.Sprintf("dispatcher-%s", adapter.SanitizeName(w.Name))

	opts := VMOptions{
		Name:       vmName,
		Region:     a.config.Region,
		SSHKeyPath: keyPath + ".pub",
		UserData:   userData,
		Tags: map[string]string{
			"dispatcher-run-id": p.Metadata.ID,
			"dispatcher":        "true",
		},
	}

	vmInfo, err := a.provider.CreateVM(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("VM creation failed: %w", err)
	}

	// Wait for SSH
	if err := a.provider.WaitReady(ctx, vmInfo.ID, vmInfo.IP, keyPath); err != nil {
		// Try to destroy on wait failure
		_ = a.provider.DestroyVM(ctx, vmInfo.ID)
		return nil, fmt.Errorf("VM not reachable via SSH: %w", err)
	}

	state := &CloudVMState{
		Provider:   a.config.ProviderID,
		VMID:       vmInfo.ID,
		IP:         vmInfo.IP,
		SSHKeyPath: keyPath,
		SSHUser:    sshUser,
		SSHPort:    22,
		Region:     a.config.Region,
		RemoteDir:  remoteDir,
		LogPath:    remoteDir + "/dispatcher.log",
		CreatedAt:  time.Now().UTC(),
	}

	// Rsync source to VM
	if err := rsyncToVM(ctx, state, w.Source.Path); err != nil {
		_ = a.provider.DestroyVM(ctx, vmInfo.ID)
		return nil, fmt.Errorf("rsync failed: %w", err)
	}

	// Start workload
	if err := startWorkloadOnVM(ctx, state, w); err != nil {
		_ = a.provider.DestroyVM(ctx, vmInfo.ID)
		return nil, fmt.Errorf("workload start failed: %w", err)
	}

	return &adapter.RunHandle{
		ID:       vmInfo.ID,
		TargetID: a.targetID,
		State:    state,
	}, nil
}

func (a *CloudVMAdapter) Status(ctx context.Context, h *adapter.RunHandle) (types.RunState, error) {
	state := h.State.(*CloudVMState)

	// Check if VM still exists
	vmInfo, err := a.provider.GetVM(ctx, state.VMID)
	if err != nil {
		return types.RunStateExecutionFailed, fmt.Errorf("cannot get VM status: %w", err)
	}

	if vmInfo.State == VMStateTerminated {
		return types.RunStateExecutionFailed, nil
	}

	// Check if workload process is still running
	if state.WorkloadPID > 0 {
		checkCmd := fmt.Sprintf("kill -0 %d 2>/dev/null && echo running || echo done", state.WorkloadPID)
		args := sshCmdArgs(state, checkCmd)
		output, err := exec.CommandContext(ctx, "ssh", args...).Output()
		if err != nil {
			return types.RunStateExecutionFailed, nil
		}
		if strings.TrimSpace(string(output)) == "done" {
			return types.RunStateCompleted, nil
		}
	}

	return types.RunStateRunning, nil
}

func (a *CloudVMAdapter) Logs(ctx context.Context, h *adapter.RunHandle, w io.Writer) error {
	state := h.State.(*CloudVMState)
	tailCmd := fmt.Sprintf("tail -f %s 2>/dev/null", state.LogPath)
	args := sshCmdArgs(state, tailCmd)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdout = w
	cmd.Stderr = w
	return cmd.Run()
}

func (a *CloudVMAdapter) Artifacts(_ context.Context, _ *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
	return nil, nil
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

	if err := a.provider.DestroyVM(ctx, state.VMID); err != nil {
		return &adapter.CleanupResult{
			Success: false,
			Errors:  []string{err.Error()},
		}, nil
	}

	// Remove ephemeral SSH key
	_ = os.Remove(state.SSHKeyPath)
	_ = os.Remove(state.SSHKeyPath + ".pub")

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

func (a *CloudVMAdapter) ListResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	vms, err := a.provider.ListVMs(ctx, map[string]string{"dispatcher": "true"})
	if err != nil {
		return nil, err
	}

	var resources []adapter.ResourceInfo
	for _, vm := range vms {
		resources = append(resources, adapter.ResourceInfo{
			ResourceID: vm.ID,
			Provider:   string(a.config.ProviderID),
			CreatedAt:  vm.CreatedAt,
			RunID:      vm.Tags["dispatcher-run-id"],
			Tags:       vm.Tags,
		})
	}
	return resources, nil
}

func (a *CloudVMAdapter) DestroyResource(ctx context.Context, resourceID string) error {
	return a.provider.DestroyVM(ctx, resourceID)
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
	default:
		return 0.10
	}
}

func generateSSHKey(runID string) (string, error) {
	keyDir, err := statedir.Subdir("keys")
	if err != nil {
		return "", err
	}
	keyPath := filepath.Join(keyDir, "dispatcher-"+runID)

	// Generate ed25519 key
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-q")
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh-keygen failed: %w", err)
	}

	return keyPath, nil
}

func rsyncToVM(ctx context.Context, state *CloudVMState, sourcePath string) error {
	// Create remote directory
	mkdirCmd := fmt.Sprintf("mkdir -p %s", adapter.ShellQuote(state.RemoteDir))
	args := sshCmdArgs(state, mkdirCmd)
	if err := exec.CommandContext(ctx, "ssh", args...).Run(); err != nil {
		return fmt.Errorf("mkdir failed: %w", err)
	}

	// Rsync with progress and .dispatchignore exclusions
	dest := fmt.Sprintf("%s@%s:%s/", state.SSHUser, state.IP, state.RemoteDir)
	rsyncArgs := []string{
		"-az", "--delete", "--progress",
		"-e", fmt.Sprintf("ssh -i %s -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
			state.SSHKeyPath, state.SSHPort),
	}
	// Common exclusions
	for _, ex := range []string{".git", "node_modules", ".venv", "venv", "__pycache__", ".dispatcher"} {
		rsyncArgs = append(rsyncArgs, "--exclude", ex)
	}
	// Read .dispatchignore if present
	patterns, _ := workload.LoadIgnorePatterns(sourcePath)
	for _, p := range patterns {
		rsyncArgs = append(rsyncArgs, "--exclude", p)
	}
	rsyncArgs = append(rsyncArgs, sourcePath+"/", dest)
	cmd := exec.CommandContext(ctx, "rsync", rsyncArgs...)
	cmd.Stdout = os.Stderr // progress to stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rsync failed: %w", err)
	}
	return nil
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

	envPrefix, err := adapter.DotEnvShellPrefix(w.Source.Path)
	if err != nil {
		return err
	}

	// Run via nohup with output to log file
	remoteCmd := fmt.Sprintf(
		"cd %s && nohup %s%s > %s 2>&1 & echo $!",
		adapter.ShellQuote(state.RemoteDir), envPrefix, cmdStr, adapter.ShellQuote(state.LogPath),
	)

	args := sshCmdArgs(state, remoteCmd)
	output, err := exec.CommandContext(ctx, "ssh", args...).Output()
	if err != nil {
		return fmt.Errorf("start failed: %w", err)
	}

	// Parse PID
	pidStr := strings.TrimSpace(string(output))
	var pid int
	fmt.Sscanf(pidStr, "%d", &pid)
	state.WorkloadPID = pid

	return nil
}

