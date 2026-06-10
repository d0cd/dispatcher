package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
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

	// Wait for pod to be running
	if err := k.waitForPod(ctx, jobName); err != nil {
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
	cmd := exec.CommandContext(ctx, "kubectl", "get", "job", vmID,
		"-n", k.namespace, "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
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
	selector := "dispatcher=true"
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

func (k *KubernetesProvider) buildJobManifest(name, image string, opts VMOptions) string {
	// Build labels
	labels := `    dispatcher: "true"`
	for key, val := range opts.Tags {
		labels += fmt.Sprintf("\n    %s: \"%s\"", key, val)
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
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels:
%s
    spec:
      restartPolicy: Never
      containers:
      - name: workload
        image: %s
        command: ["sleep", "86400"]
`, name, k.namespace, labels, labels, image)

	return manifest
}

func (k *KubernetesProvider) waitForPod(ctx context.Context, jobName string) error {
	deadline := time.After(5 * time.Minute)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for pod to be running")
		case <-ticker.C:
			cmd := exec.CommandContext(ctx, "kubectl", "get", "pods",
				"-n", k.namespace, "-l", "job-name="+jobName,
				"-o", "jsonpath={.items[0].status.phase}")
			output, err := cmd.Output()
			if err != nil {
				continue
			}
			phase := strings.TrimSpace(string(output))
			if phase == "Running" {
				return nil
			}
			if phase == "Failed" || phase == "Error" {
				return fmt.Errorf("pod failed to start (phase: %s)", phase)
			}
		}
	}
}
