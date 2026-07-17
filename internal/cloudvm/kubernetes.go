package cloudvm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// KubernetesProvider implements Provider using kubectl for Kubernetes Jobs.
// VMs are modeled as Kubernetes Jobs — CreateVM submits a Job, DestroyVM deletes it.
type KubernetesProvider struct {
	namespace string
}

// NewKubernetesProvider creates a new Kubernetes provider.
func NewKubernetesProvider(namespace string) *KubernetesProvider {
	if namespace == "" {
		namespace = "default"
	}
	return &KubernetesProvider{namespace: namespace}
}

func (k *KubernetesProvider) Name() ProviderID { return ProviderKubernetes }

func (k *KubernetesProvider) CheckCLI(ctx context.Context) error {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return fmt.Errorf("kubectl not found: %w", err)
	}
	cmd := exec.CommandContext(ctx, "kubectl", "cluster-info")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl cannot reach cluster: %w", err)
	}
	return nil
}

func (k *KubernetesProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	image := opts.Image
	if image == "" {
		image = "ubuntu:24.04"
	}

	if opts.AllowSSHFrom != "" {
		return nil, errFirewallUnsupported("kubernetes")
	}

	// The manifest is built by string interpolation, so every interpolated
	// value must be validated at the boundary — an unvalidated image ref, job
	// name, or tag containing a newline could inject arbitrary Pod spec
	// (privileged, hostPath, hostNetwork) into the operator's cluster.
	if !isSafeArg(image) {
		return nil, fmt.Errorf("kubernetes image %q contains characters outside [a-zA-Z0-9_.:/@-] or is empty/flag-like", image)
	}
	if !isSafeArg(opts.Name) {
		return nil, fmt.Errorf("kubernetes job name %q contains characters outside [a-zA-Z0-9_.:/@-] or is empty/flag-like", opts.Name)
	}
	if err := validateLabels(opts.Tags); err != nil {
		return nil, fmt.Errorf("kubernetes labels: %w", err)
	}

	// Build a Job manifest
	jobName := opts.Name
	manifest := k.buildJobManifest(jobName, image, opts)

	// Apply via stdin
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-n", k.namespace, "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("kubectl apply failed: %s: %w", string(output), err)
	}

	// Wait for the init container to be running so dispatcher can copy source
	// into it and signal readiness (the workload container starts after that).
	if err := k.waitForInitRunning(ctx, jobName); err != nil {
		_ = k.DestroyVM(ctx, jobName)
		return nil, err
	}

	return &VMInfo{
		ID:        jobName,
		Name:      jobName,
		IP:        jobName, // For k8s, we use kubectl exec instead of SSH, so "IP" is the pod name
		State:     VMStateRunning,
		CreatedAt: time.Now().UTC(),
		Tags:      opts.Tags,
	}, nil
}

func (k *KubernetesProvider) WaitReady(ctx context.Context, _ string, _ string, _ string) error {
	// Already waited in CreateVM
	return nil
}

func (k *KubernetesProvider) GetVM(ctx context.Context, vmID string) (*VMInfo, error) {
	output, err := runCLI(ctx, "kubectl", "get", "job", vmID, "-n", k.namespace, "-o", "json")
	if err != nil {
		if isVMNotFound(err, vmID) {
			// The Job vanished (deleted / TTL-GC'd). We can't confirm it
			// succeeded, so this is NOT a completion — report Error, never
			// Terminated (which Status maps to a successful Completed).
			return &VMInfo{ID: vmID, State: VMStateError}, nil
		}
		// Transient/unexpected kubectl failure: propagate so the executor's
		// poll tolerance handles it rather than declaring the run finished.
		return nil, wrapExecError("kubectl get job", err)
	}

	var job struct {
		Status struct {
			Active    int `json:"active"`
			Succeeded int `json:"succeeded"`
			Failed    int `json:"failed"`
		} `json:"status"`
	}
	if err := json.Unmarshal(output, &job); err != nil {
		return nil, err
	}

	state := VMStateRunning
	if job.Status.Succeeded > 0 {
		state = VMStateTerminated
	}
	if job.Status.Failed > 0 {
		state = VMStateError
	}
	if job.Status.Active == 0 && job.Status.Succeeded == 0 && job.Status.Failed == 0 {
		state = VMStatePending
	}

	return &VMInfo{ID: vmID, Name: vmID, State: state}, nil
}

func (k *KubernetesProvider) DestroyVM(ctx context.Context, vmID string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "delete", "job", vmID,
		"-n", k.namespace, "--ignore-not-found")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl delete job failed: %w", err)
	}
	return nil
}

func (k *KubernetesProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	// Honor the caller's tag filter (e.g. a run-scoped reap) in addition to the
	// dispatcher-ownership label; ignoring it would return every dispatcher Job
	// across all runs, not just the requested one.
	parts := []string{"dispatcher=true"}
	for key, val := range tags {
		if key == "dispatcher" {
			continue
		}
		parts = append(parts, key+"="+val)
	}
	sort.Strings(parts) // deterministic argv
	selector := strings.Join(parts, ",")
	cmd := exec.CommandContext(ctx, "kubectl", "get", "jobs",
		"-n", k.namespace, "-l", selector, "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get jobs failed: %w", err)
	}

	var result struct {
		Items []struct {
			Metadata struct {
				Name              string            `json:"name"`
				Labels            map[string]string `json:"labels"`
				CreationTimestamp string            `json:"creationTimestamp"`
			} `json:"metadata"`
			Status struct {
				Active int `json:"active"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	var vms []VMInfo
	for _, item := range result.Items {
		created, _ := time.Parse(time.RFC3339, item.Metadata.CreationTimestamp)
		state := VMStateRunning
		if item.Status.Active == 0 {
			state = VMStateTerminated
		}
		vms = append(vms, VMInfo{
			ID:        item.Metadata.Name,
			Name:      item.Metadata.Name,
			State:     state,
			CreatedAt: created,
			Tags:      item.Metadata.Labels,
		})
	}
	return vms, nil
}

const (
	k8sWorkspaceDir = "/workspace"
	k8sReadyMarker  = "/workspace/.dispatcher-ready"
	k8sLogFile      = "/workspace/dispatcher.log"
	k8sInitName     = "dispatcher-init"
)

// k8sInitScript blocks until dispatcher has copied the source and dropped the
// ready marker into the shared volume, so the workload container starts only
// once its inputs are in place.
func k8sInitScript() string {
	return fmt.Sprintf("while [ ! -f %s ]; do sleep 1; done", k8sReadyMarker)
}

// k8sWorkloadScript is the main container command: decode and run the workload
// as the container's process so the Job's success/failure reflects the
// workload's exit code. Output goes to the container's stdout/stderr so `kubectl
// logs` can retrieve it during AND after the run (kubelet retains it until the
// Job is GC'd) — a file in the emptyDir would vanish when the pod terminates.
// The command is base64-encoded so no shell/YAML metacharacter breaks the manifest.
func k8sWorkloadScript(command string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(command))
	return fmt.Sprintf("echo %s | base64 -d | sh", encoded)
}

func (k *KubernetesProvider) buildJobManifest(name, image string, opts VMOptions) string {
	// Labels render at two depths: 4 spaces under the Job's metadata.labels and
	// 8 spaces under template.metadata.labels. Reusing one block under-indents
	// the pod-template labels, dropping them (and injecting stray keys).
	topLabels := k8sLabelBlock(opts.Tags, "    ")
	podLabels := k8sLabelBlock(opts.Tags, "        ")

	// Hard runtime ceiling from MaxDuration; omitted when unset (the workload
	// runs to completion and orphans are reclaimed by `dispatcher gc`).
	deadlineLine := ""
	if opts.MaxLifetimeSeconds > 0 {
		deadlineLine = fmt.Sprintf("\n  activeDeadlineSeconds: %d", opts.MaxLifetimeSeconds)
	}

	// GPU request so k8s schedules onto a GPU node instead of silently using CPU.
	gpuBlock := ""
	if opts.GPUCount > 0 {
		gpuBlock = fmt.Sprintf("\n        resources:\n          limits:\n            nvidia.com/gpu: \"%d\"", opts.GPUCount)
	}

	manifest := fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: %s
  labels:
%s
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 300%s
  template:
    metadata:
      labels:
%s
    spec:
      restartPolicy: Never
      volumes:
      - name: workspace
        emptyDir: {}
      initContainers:
      - name: %s
        image: %s
        command: ["sh", "-c", "%s"]
        volumeMounts:
        - name: workspace
          mountPath: %s
      containers:
      - name: workload
        image: %s
        workingDir: %s
        command: ["sh", "-c", "%s"]%s
        volumeMounts:
        - name: workspace
          mountPath: %s
`, name, k.namespace, topLabels, deadlineLine, podLabels,
		k8sInitName, image, k8sInitScript(), k8sWorkspaceDir,
		image, k8sWorkspaceDir, k8sWorkloadScript(opts.Command), gpuBlock, k8sWorkspaceDir)

	return manifest
}

// k8sLabelBlock renders the dispatcher label set at the given indentation.
func k8sLabelBlock(tags map[string]string, indent string) string {
	block := indent + `dispatcher: "true"`
	for key, val := range tags {
		block += fmt.Sprintf("\n%s%s: \"%s\"", indent, key, val)
	}
	return block
}

func (k *KubernetesProvider) waitForInitRunning(ctx context.Context, jobName string) error {
	deadline := time.After(5 * time.Minute)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for init container to start")
		case <-ticker.C:
			cmd := exec.CommandContext(ctx, "kubectl", "get", "pods",
				"-n", k.namespace, "-l", "job-name="+jobName,
				"-o", "jsonpath={.items[0].status.initContainerStatuses[0].state.running.startedAt}")
			if out, err := cmd.Output(); err == nil && strings.TrimSpace(string(out)) != "" {
				return nil
			}
			// Bail out if the pod has already failed (e.g. image pull error).
			pcmd := exec.CommandContext(ctx, "kubectl", "get", "pods",
				"-n", k.namespace, "-l", "job-name="+jobName,
				"-o", "jsonpath={.items[0].status.phase}")
			if pout, perr := pcmd.Output(); perr == nil {
				if phase := strings.TrimSpace(string(pout)); phase == "Failed" {
					return fmt.Errorf("pod failed before init container started")
				}
			}
		}
	}
}
