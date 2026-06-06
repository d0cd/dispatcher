package workload

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLoadConfig_Found(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", `
name: my-app
command: ["python3", "app.py"]
maxCost: 10
gpu:
  count: 1
  model: a100
service:
  port: 8080
`)

	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "my-app", cfg.Name)
	assert.Equal(t, []string{"python3", "app.py"}, cfg.Command)
	assert.Equal(t, 10.0, cfg.MaxCost)
	assert.Equal(t, 1, cfg.GPU.Count)
	assert.Equal(t, "a100", cfg.GPU.Model)
	assert.Equal(t, 8080, cfg.Service.Port)
}

func TestLoadConfig_NotFound(t *testing.T) {
	cfg, err := LoadConfig(t.TempDir())
	assert.NoError(t, err)
	assert.Nil(t, cfg)
}

func TestLoadConfig_YmlExtension(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yml", "name: yml-app\n")

	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "yml-app", cfg.Name)
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", "{{invalid yaml")

	_, err := LoadConfig(dir)
	assert.Error(t, err)
}

func TestApplyConfig_Name(t *testing.T) {
	spec := &types.WorkloadSpec{Name: "auto-detected"}
	ApplyConfig(spec, &DispatcherConfig{Name: "my-custom-name"})
	assert.Equal(t, "my-custom-name", spec.Name)
}

func TestApplyConfig_Command(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatcherConfig{Command: []string{"python3", "train.py"}})
	assert.Equal(t, []string{"python3", "train.py"}, spec.Command)
}

func TestApplyConfig_GPU(t *testing.T) {
	spec := &types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	ApplyConfig(spec, &DispatcherConfig{
		GPU: &DispatchGPUConfig{Count: 2, Model: "h100"},
	})
	assert.True(t, spec.Requirements.GPU.Required)
	assert.Equal(t, 2, spec.Requirements.GPU.Count)
	assert.Equal(t, "h100", spec.Requirements.GPU.Model)
	assert.Equal(t, types.WorkloadKindGPUJob, spec.DetectedKind)
}

func TestApplyConfig_GPU_DefaultCount(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatcherConfig{
		GPU: &DispatchGPUConfig{Model: "a100"},
	})
	assert.Equal(t, 1, spec.Requirements.GPU.Count)
}

func TestApplyConfig_Service(t *testing.T) {
	spec := &types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	ApplyConfig(spec, &DispatcherConfig{
		Service: &DispatchService{Port: 3000},
	})
	assert.Contains(t, spec.Ports, 3000)
	assert.Equal(t, types.WorkloadKindService, spec.DetectedKind)
}

func TestApplyConfig_ServiceNoDuplicate(t *testing.T) {
	spec := &types.WorkloadSpec{Ports: []int{3000}}
	ApplyConfig(spec, &DispatcherConfig{
		Service: &DispatchService{Port: 3000},
	})
	// Should not add duplicate
	count := 0
	for _, p := range spec.Ports {
		if p == 3000 {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestApplyConfig_Sandbox(t *testing.T) {
	spec := &types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	ApplyConfig(spec, &DispatcherConfig{Sandbox: true})
	assert.Equal(t, types.WorkloadKindSandbox, spec.DetectedKind)
}

func TestApplyConfig_Nil(t *testing.T) {
	spec := &types.WorkloadSpec{Name: "original"}
	ApplyConfig(spec, nil)
	assert.Equal(t, "original", spec.Name)
}

func TestApplyConfig_Outputs(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatcherConfig{Outputs: []string{"results/", "model.bin"}})
	assert.Equal(t, []string{"results/", "model.bin"}, spec.Outputs,
		"explicit outputs config should populate spec.Outputs")
}

func TestApplyConfig_Outputs_RejectsTraversal(t *testing.T) {
	// Path traversal in outputs is the artifact-exfiltration vector. The
	// rsync in CloudVMAdapter.Artifacts would otherwise pull arbitrary
	// remote paths back to the local machine. Reject at config load.
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatcherConfig{Outputs: []string{
		"results/",         // ok
		"../etc/passwd",    // traversal
		"/etc/shadow",      // absolute
		"sub/../../../etc", // sneaky traversal
		"model.bin",        // ok
	}})
	assert.Equal(t, []string{"results/", "model.bin"}, spec.Outputs,
		"traversal/absolute entries should be dropped")
}

func TestApplyConfig_Outputs_EmptyDropped(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatcherConfig{Outputs: []string{"", "results/"}})
	assert.Equal(t, []string{"results/"}, spec.Outputs)
}

// TestApplyConfig_Image_PopulatesBaseImage verifies the pre-built-image
// path: cfg.Image must land on spec.Package.BaseImage so the docker
// adapter can actually run it. Before this fix, the value was silently
// dropped — `image:` in dispatcher.yaml was a no-op.
func TestApplyConfig_Image_PopulatesBaseImage(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatcherConfig{Image: "nginx:alpine"})
	assert.Equal(t, types.PackageTypeImage, spec.Package.Type)
	assert.Equal(t, "nginx:alpine", spec.Package.BaseImage)
	assert.False(t, spec.Package.BuildRequired,
		"pre-built images shouldn't trigger a build step")
}

func TestApplyConfig_WatchdogTTL(t *testing.T) {
	// WatchdogTTL is parsed in plan.Build; ApplyConfig just carries it on
	// the cfg struct. This test verifies the field round-trips through YAML
	// unmarshal.
	yamlBody := []byte("watchdogTtl: 15m\n")
	var cfg DispatcherConfig
	require.NoError(t, yaml.Unmarshal(yamlBody, &cfg))
	assert.Equal(t, "15m", cfg.WatchdogTTL)
}

func TestInspectCodebase_WithDispatchYaml(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hello")`)
	writeFile(t, dir, "dispatcher.yaml", `
name: configured-app
command: ["python3", "main.py", "--prod"]
service:
  port: 9090
maxCost: 25
`)

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)

	assert.Equal(t, "configured-app", spec.Name)
	assert.Equal(t, []string{"python3", "main.py", "--prod"}, spec.Command)
	assert.Contains(t, spec.Ports, 9090)
	assert.Equal(t, types.WorkloadKindService, spec.DetectedKind)
}

func TestInspectCodebase_ConfigOverridesDetection(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hello")`)
	writeFile(t, dir, "dispatcher.yaml", `
gpu:
  count: 2
  model: a100
  framework: pytorch
`)

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)

	assert.Equal(t, types.WorkloadKindGPUJob, spec.DetectedKind)
	assert.True(t, spec.Requirements.GPU.Required)
	assert.Equal(t, 2, spec.Requirements.GPU.Count)
}
