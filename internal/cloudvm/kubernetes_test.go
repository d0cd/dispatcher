package cloudvm

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func parseManifest(t *testing.T, m string) map[string]any {
	t.Helper()
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(m), &doc), "manifest must be valid YAML")
	return doc
}

// The rendered manifest must be structurally valid: the pod template's labels
// must land under template.metadata.labels, not leak in as stray top-level keys
// from a reused (under-indented) label block.
func TestBuildJobManifest_PodTemplateLabelsWellFormed(t *testing.T) {
	k := NewKubernetesProvider("default")
	opts := VMOptions{
		Name: "j", Image: "ubuntu", Command: "echo hi",
		Tags: map[string]string{"dispatcher-run-id": "run_1"},
	}

	doc := parseManifest(t, k.buildJobManifest(opts.Name, opts.Image, opts))
	spec, _ := doc["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	require.NotNil(t, tmpl)
	assert.ElementsMatch(t, []string{"metadata", "spec"}, keysOf(tmpl),
		"pod template must have only metadata+spec (no misindented label keys leaking in)")

	meta, _ := tmpl["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	assert.Equal(t, "true", labels["dispatcher"], "pod template must carry its labels")
	assert.Equal(t, "run_1", labels["dispatcher-run-id"])
}

// The workload runs as the Job's MAIN container (so Job success/failure reflects
// the workload's exit), with source delivered by an init container that blocks
// until a ready marker appears in a shared volume.
func TestBuildJobManifest_RunsWorkloadAsMainContainer(t *testing.T) {
	k := NewKubernetesProvider("default")
	opts := VMOptions{
		Name: "j", Image: "ubuntu:24.04", Command: "python main.py",
		MaxLifetimeSeconds: 3600,
		Tags:               map[string]string{"dispatcher-run-id": "run_1"},
	}

	m := k.buildJobManifest(opts.Name, opts.Image, opts)
	doc := parseManifest(t, m)
	spec := doc["spec"].(map[string]any)

	assert.Equal(t, 3600, spec["activeDeadlineSeconds"], "hard cap from MaxDuration")
	assert.NotContains(t, m, "sleep 86400", "no keep-alive sleep")

	podSpec := spec["template"].(map[string]any)["spec"].(map[string]any)

	inits, _ := podSpec["initContainers"].([]any)
	require.Len(t, inits, 1)
	assert.Contains(t, fmt.Sprint(inits[0].(map[string]any)["command"]), k8sReadyMarker,
		"init container waits for the ready marker")

	containers, _ := podSpec["containers"].([]any)
	require.Len(t, containers, 1)
	wlCmd := fmt.Sprint(containers[0].(map[string]any)["command"])
	assert.Contains(t, wlCmd, base64.StdEncoding.EncodeToString([]byte("python main.py")),
		"workload command is embedded base64-safe")
	assert.Contains(t, wlCmd, "base64 -d", "and decoded at runtime")

	vols, _ := podSpec["volumes"].([]any)
	require.Len(t, vols, 1, "shared workspace volume")
}

func TestBuildJobManifest_NoDeadlineWhenMaxLifetimeUnset(t *testing.T) {
	k := NewKubernetesProvider("default")
	opts := VMOptions{Name: "j", Image: "ubuntu", Command: "echo hi"}

	m := k.buildJobManifest(opts.Name, opts.Image, opts)

	assert.NotContains(t, m, "activeDeadlineSeconds", "no hard cap when MaxDuration is unset")
}

// A GPU workload must request nvidia.com/gpu so k8s schedules it on a GPU node
// (or leaves it Pending) instead of silently running on a CPU pod.
func TestBuildJobManifest_RequestsGPUWhenRequired(t *testing.T) {
	k := NewKubernetesProvider("default")
	opts := VMOptions{Name: "j", Image: "ubuntu", Command: "train", GPUCount: 2}

	doc := parseManifest(t, k.buildJobManifest(opts.Name, opts.Image, opts))
	container := doc["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	limits, _ := container["resources"].(map[string]any)["limits"].(map[string]any)

	require.NotNil(t, limits, "GPU workload must set resource limits")
	assert.Equal(t, "2", fmt.Sprint(limits["nvidia.com/gpu"]))
}

func TestBuildJobManifest_NoGPUResourcesWhenNotRequired(t *testing.T) {
	k := NewKubernetesProvider("default")
	opts := VMOptions{Name: "j", Image: "ubuntu", Command: "echo hi"}

	assert.NotContains(t, k.buildJobManifest(opts.Name, opts.Image, opts), "nvidia.com/gpu")
}

// A transient kubectl error must NOT be reported as a completed Job — the old
// behavior mapped any error to Terminated, which K8sAdapter.Status turned into a
// silent success (killing the still-running Job). It must propagate.
func TestK8sGetVM_TransientErrorPropagates(t *testing.T) {
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })
	runCLI = func(context.Context, string, ...string) ([]byte, error) {
		return nil, fmt.Errorf("Unable to connect to the server: dial tcp: i/o timeout")
	}
	k := NewKubernetesProvider("default")
	_, err := k.GetVM(context.Background(), "job-x")
	require.Error(t, err, "a transient kubectl error must propagate, not report the Job gone")
}

// A vanished (NotFound) Job is not a success — it must not map to Terminated
// (which Status treats as Completed).
func TestK8sGetVM_VanishedJobIsNotSuccess(t *testing.T) {
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })
	runCLI = func(context.Context, string, ...string) ([]byte, error) {
		return nil, fmt.Errorf(`Error from server (NotFound): jobs.batch "job-x" not found`)
	}
	k := NewKubernetesProvider("default")
	vm, err := k.GetVM(context.Background(), "job-x")
	require.NoError(t, err)
	assert.NotEqual(t, VMStateTerminated, vm.State, "a vanished Job must not be reported as a successful completion")
}
