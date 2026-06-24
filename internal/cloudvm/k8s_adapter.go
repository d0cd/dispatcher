package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/types"
)

// K8sState is the serializable state for Kubernetes runs.
type K8sState struct {
	JobName   string `json:"jobName"`
	Namespace string `json:"namespace"`
	PodName   string `json:"podName"`
	RemoteDir string `json:"remoteDir"`
	LogPath   string `json:"logPath"`
}

func (s *K8sState) MarshalHandleState() (json.RawMessage, error) {
	return json.Marshal(s)
}

// K8sAdapter runs workloads as Kubernetes Jobs using kubectl.
type K8sAdapter struct {
	provider  *KubernetesProvider
	namespace string
}

// NewK8sAdapter creates a Kubernetes adapter.
func NewK8sAdapter(namespace string) *K8sAdapter {
	if namespace == "" {
		namespace = "default"
	}
	return &K8sAdapter{
		provider:  NewKubernetesProvider(namespace),
		namespace: namespace,
	}
}

func (a *K8sAdapter) ID() string { return "kubernetes" }

func (a *K8sAdapter) Validate(ctx context.Context, w types.WorkloadSpec) (types.ValidationResult, error) {
	v := adapter.DefaultValidationResult()
	if err := a.provider.CheckCLI(ctx); err != nil {
		v.Credentials = types.ValidationFail
		return v, fmt.Errorf("kubernetes check failed: %w", err)
	}
	return v, nil
}

func (a *K8sAdapter) EstimateCost(_ context.Context, w types.WorkloadSpec) (types.CostEstimate, error) {
	hours := 1.0
	if w.DetectedKind == types.WorkloadKindService {
		hours = 24.0
	}
	total := 0.10 * hours // ~$0.10/hr for a small pod
	total = float64(int(total*100)) / 100
	return types.CostEstimate{
		Value:       total,
		Currency:    "USD",
		Confidence:  types.ConfidenceMedium,
		Assumptions: []string{fmt.Sprintf("assumes %.0fh runtime on shared cluster", hours)},
	}, nil
}

func (a *K8sAdapter) Prepare(_ context.Context, _ *types.Plan) error {
	return nil
}

func (a *K8sAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	w := p.Workload
	jobName := fmt.Sprintf("dispatcher-%s", adapter.SanitizeName(w.Name))

	image := "ubuntu:24.04"
	if w.Package.BaseImage != "" {
		image = w.Package.BaseImage
	}

	// The workload runs as the Job's main container, so its command goes into the
	// manifest — build it before creating the Job.
	var cmdStr string
	if len(w.Command) > 0 {
		cmdStr = adapter.ShellQuoteArgs(w.Command)
	} else if len(w.Entrypoints) > 0 {
		cmdStr = adapter.ShellQuoteArgs(adapter.RuntimeCommand(w.Runtime, w.Entrypoints[0], true))
	} else {
		return nil, fmt.Errorf("no command or entrypoint")
	}

	gpuCount := 0
	if w.Requirements.GPU.Required {
		gpuCount = w.Requirements.GPU.Count
		if gpuCount == 0 {
			gpuCount = 1
		}
	}

	vmInfo, err := a.provider.CreateVM(ctx, VMOptions{
		Name:               jobName,
		Image:              image,
		Command:            cmdStr,
		MaxLifetimeSeconds: int(p.Constraints.MaxDuration.Seconds()),
		GPUCount:           gpuCount,
		Tags: map[string]string{
			"dispatcher":        "true",
			"dispatcher-run-id": p.Metadata.ID,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("job creation failed: %w", err)
	}

	podName, err := a.getPodName(ctx, jobName)
	if err != nil {
		_ = a.provider.DestroyVM(ctx, jobName)
		return nil, fmt.Errorf("cannot find pod: %w", err)
	}

	// Deliver source into the shared volume via the init container, then drop the
	// ready marker so the init container exits and the workload container starts.
	if w.Source.Path != "" {
		if err := a.copyToInit(ctx, podName, w.Source.Path); err != nil {
			_ = a.provider.DestroyVM(ctx, jobName)
			return nil, fmt.Errorf("file copy failed: %w", err)
		}
	}
	if err := a.signalReady(ctx, podName); err != nil {
		_ = a.provider.DestroyVM(ctx, jobName)
		return nil, fmt.Errorf("failed to start workload: %w", err)
	}

	state := &K8sState{
		JobName:   jobName,
		Namespace: a.namespace,
		PodName:   podName,
		RemoteDir: k8sWorkspaceDir,
		LogPath:   k8sLogFile,
	}
	return &adapter.RunHandle{ID: vmInfo.ID, TargetID: "kubernetes", State: state}, nil
}

func (a *K8sAdapter) Status(ctx context.Context, h *adapter.RunHandle) (types.RunState, error) {
	state := h.State.(*K8sState)
	vmInfo, err := a.provider.GetVM(ctx, state.JobName)
	if err != nil {
		return types.RunStateExecutionFailed, err
	}
	switch vmInfo.State {
	case VMStateTerminated:
		return types.RunStateCompleted, nil
	case VMStateError:
		return types.RunStateExecutionFailed, nil
	default:
		return types.RunStateRunning, nil
	}
}

func (a *K8sAdapter) Logs(ctx context.Context, h *adapter.RunHandle, w io.Writer) error {
	state := h.State.(*K8sState)
	// kubectl logs reads the workload container's stdout/stderr, which the
	// kubelet retains after the container terminates (until the Job is GC'd) —
	// unlike exec-cat, which fails once the pod is gone.
	cmd := exec.CommandContext(ctx, "kubectl", "logs", state.PodName,
		"-c", "workload", "-n", a.namespace)
	cmd.Stdout = w
	cmd.Stderr = w
	return cmd.Run()
}

func (a *K8sAdapter) Artifacts(_ context.Context, _ *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
	return nil, nil
}

func (a *K8sAdapter) Terminate(ctx context.Context, h *adapter.RunHandle) error {
	state := h.State.(*K8sState)
	return a.provider.DestroyVM(ctx, state.JobName)
}

// FailureDetails reads exit code and termination signal from the pod's
// container status. Without this, k8s failures classify as "unknown" and
// the retry-transient logic never fires for them.
func (a *K8sAdapter) FailureDetails(h *adapter.RunHandle) adapter.FailureDetails {
	state, ok := h.State.(*K8sState)
	if !ok {
		return adapter.FailureDetails{Message: "no k8s state"}
	}
	cmd := exec.Command("kubectl", "get", "pod", state.PodName,
		"-n", state.Namespace,
		"-o", "jsonpath={.status.containerStatuses[0].state.terminated}")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return adapter.FailureDetails{Message: "pod state unavailable (pod already gc'd or kubectl unreachable)"}
	}
	var term struct {
		ExitCode int    `json:"exitCode"`
		Reason   string `json:"reason"`
		Signal   int    `json:"signal"`
	}
	if err := json.Unmarshal(out, &term); err != nil {
		return adapter.FailureDetails{Message: fmt.Sprintf("parse pod state: %v", err)}
	}
	fd := adapter.FailureDetails{ExitCode: term.ExitCode}
	if term.Reason == "OOMKilled" {
		fd.OOMKilled = true
		fd.Message = "container OOMKilled"
	} else if term.Signal != 0 {
		fd.Signal = fmt.Sprintf("signal-%d", term.Signal)
		fd.Message = fmt.Sprintf("container killed by signal %d", term.Signal)
	} else if term.ExitCode != 0 {
		fd.Message = fmt.Sprintf("container exited with code %d (%s)", term.ExitCode, term.Reason)
	}
	return fd
}

func (a *K8sAdapter) Cleanup(ctx context.Context, h *adapter.RunHandle) (*adapter.CleanupResult, error) {
	state := h.State.(*K8sState)
	if err := a.provider.DestroyVM(ctx, state.JobName); err != nil {
		return &adapter.CleanupResult{Success: false, Errors: []string{err.Error()}}, nil
	}
	return &adapter.CleanupResult{Success: true, ResourcesCleaned: []string{state.JobName}}, nil
}

// DurableAdapter methods

func (a *K8sAdapter) Reconnect(_ context.Context, handleID string, raw json.RawMessage) (*adapter.RunHandle, error) {
	var state K8sState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	return &adapter.RunHandle{ID: handleID, TargetID: "kubernetes", State: &state}, nil
}

func (a *K8sAdapter) ExtendWatchdog(_ context.Context, _ *adapter.RunHandle, _ time.Duration) (time.Time, error) {
	// k8s Jobs are bounded by a fixed activeDeadlineSeconds, not a renewable
	// watchdog; orphans are reclaimed by `dispatcher gc`. Report honestly so
	// status/renew don't claim a renewal that didn't happen.
	return time.Time{}, fmt.Errorf("kubernetes runs use a fixed deadline, not a renewable watchdog")
}

func (a *K8sAdapter) ListResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	vms, err := a.provider.ListVMs(ctx, map[string]string{"dispatcher": "true"})
	if err != nil {
		return nil, err
	}
	var resources []adapter.ResourceInfo
	for _, vm := range vms {
		resources = append(resources, adapter.ResourceInfo{
			ResourceID: vm.ID,
			Provider:   "kubernetes",
			CreatedAt:  vm.CreatedAt,
			RunID:      vm.Tags["dispatcher-run-id"],
			Tags:       vm.Tags,
		})
	}
	return resources, nil
}

func (a *K8sAdapter) DestroyResource(ctx context.Context, resourceID string) error {
	return a.provider.DestroyVM(ctx, resourceID)
}

// helpers

func (a *K8sAdapter) getPodName(ctx context.Context, jobName string) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods",
		"-n", a.namespace, "-l", "job-name="+jobName,
		"-o", "jsonpath={.items[0].metadata.name}")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("cannot get pod name: %w", err)
	}
	name := strings.TrimSpace(string(output))
	if name == "" {
		return "", fmt.Errorf("no pod found for job %s", jobName)
	}
	return name, nil
}

// copyToInit copies the workload source into the shared volume via the init
// container (the only container running while the pod waits for the ready
// marker). The emptyDir is shared, so the workload container sees the files.
func (a *K8sAdapter) copyToInit(ctx context.Context, podName, srcPath string) error {
	// Trailing "/." copies the directory's CONTENTS into /workspace rather than
	// nesting them under /workspace/<dirname>, so the workload (workingDir
	// /workspace) finds its files directly.
	cmd := exec.CommandContext(ctx, "kubectl", "cp", srcPath+"/.", podName+":"+k8sWorkspaceDir,
		"-c", k8sInitName, "-n", a.namespace)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubectl cp failed: %s: %w", string(output), err)
	}
	return nil
}

// signalReady drops the ready marker into the shared volume, releasing the init
// container so the workload container starts.
func (a *K8sAdapter) signalReady(ctx context.Context, podName string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "exec", podName, "-c", k8sInitName,
		"-n", a.namespace, "--", "touch", k8sReadyMarker)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubectl exec (signal ready) failed: %s: %w", string(output), err)
	}
	return nil
}
