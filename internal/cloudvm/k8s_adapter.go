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
	remoteDir := "/workspace"

	// Determine image
	image := "ubuntu:24.04"
	if w.Package.Dockerfile != "" || w.Package.BaseImage != "" {
		if w.Package.BaseImage != "" {
			image = w.Package.BaseImage
		}
	}

	// Create the Job
	vmInfo, err := a.provider.CreateVM(ctx, VMOptions{
		Name:  jobName,
		Image: image,
		Tags: map[string]string{
			"dispatcher":        "true",
			"dispatcher-run-id": p.Metadata.ID,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("job creation failed: %w", err)
	}

	// Get the pod name
	podName, err := a.getPodName(ctx, jobName)
	if err != nil {
		_ = a.provider.DestroyVM(ctx, jobName)
		return nil, fmt.Errorf("cannot find pod: %w", err)
	}

	// Copy source to pod
	if w.Source.Path != "" {
		if err := a.copyToPod(ctx, podName, w.Source.Path, remoteDir); err != nil {
			_ = a.provider.DestroyVM(ctx, jobName)
			return nil, fmt.Errorf("file copy failed: %w", err)
		}
	}

	// Build command
	var cmdStr string
	if len(w.Command) > 0 {
		cmdStr = adapter.ShellQuoteArgs(w.Command)
	} else if len(w.Entrypoints) > 0 {
		parts := adapter.RuntimeCommand(w.Runtime, w.Entrypoints[0], true)
		cmdStr = adapter.ShellQuoteArgs(parts)
	} else {
		_ = a.provider.DestroyVM(ctx, jobName)
		return nil, fmt.Errorf("no command or entrypoint")
	}

	logPath := remoteDir + "/dispatcher.log"

	// Start workload in background
	execCmd := fmt.Sprintf("cd %s && nohup sh -c %s > %s 2>&1 &",
		adapter.ShellQuote(remoteDir),
		adapter.ShellQuote(cmdStr),
		adapter.ShellQuote(logPath))

	kubectl := exec.CommandContext(ctx, "kubectl", "exec", podName,
		"-n", a.namespace, "--", "sh", "-c", execCmd)
	if err := kubectl.Run(); err != nil {
		_ = a.provider.DestroyVM(ctx, jobName)
		return nil, fmt.Errorf("workload start failed: %w", err)
	}

	state := &K8sState{
		JobName:   jobName,
		Namespace: a.namespace,
		PodName:   podName,
		RemoteDir: remoteDir,
		LogPath:   logPath,
	}

	return &adapter.RunHandle{
		ID:       vmInfo.ID,
		TargetID: "kubernetes",
		State:    state,
	}, nil
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
	cmd := exec.CommandContext(ctx, "kubectl", "exec", state.PodName,
		"-n", a.namespace, "--", "cat", state.LogPath)
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

func (a *K8sAdapter) ExtendWatchdog(_ context.Context, _ *adapter.RunHandle, ttl time.Duration) (time.Time, error) {
	// K8s Jobs have ttlSecondsAfterFinished; no watchdog needed
	return time.Now().Add(ttl), nil
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

func (a *K8sAdapter) copyToPod(ctx context.Context, podName, srcPath, destDir string) error {
	// kubectl cp requires tar, copies directory
	cmd := exec.CommandContext(ctx, "kubectl", "cp", srcPath, podName+":"+destDir,
		"-n", a.namespace)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubectl cp failed: %s: %w", string(output), err)
	}
	return nil
}
