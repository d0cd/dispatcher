package workload

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_Found(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatch.yaml", `
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
	writeFile(t, dir, "dispatch.yml", "name: yml-app\n")

	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "yml-app", cfg.Name)
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatch.yaml", "{{invalid yaml")

	_, err := LoadConfig(dir)
	assert.Error(t, err)
}

func TestApplyConfig_Name(t *testing.T) {
	spec := &types.WorkloadSpec{Name: "auto-detected"}
	ApplyConfig(spec, &DispatchConfig{Name: "my-custom-name"})
	assert.Equal(t, "my-custom-name", spec.Name)
}

func TestApplyConfig_Command(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatchConfig{Command: []string{"python3", "train.py"}})
	assert.Equal(t, []string{"python3", "train.py"}, spec.Command)
}

func TestApplyConfig_GPU(t *testing.T) {
	spec := &types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	ApplyConfig(spec, &DispatchConfig{
		GPU: &DispatchGPUConfig{Count: 2, Model: "h100"},
	})
	assert.True(t, spec.Requirements.GPU.Required)
	assert.Equal(t, 2, spec.Requirements.GPU.Count)
	assert.Equal(t, "h100", spec.Requirements.GPU.Model)
	assert.Equal(t, types.WorkloadKindGPUJob, spec.DetectedKind)
}

func TestApplyConfig_GPU_DefaultCount(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatchConfig{
		GPU: &DispatchGPUConfig{Model: "a100"},
	})
	assert.Equal(t, 1, spec.Requirements.GPU.Count)
}

func TestApplyConfig_Service(t *testing.T) {
	spec := &types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	ApplyConfig(spec, &DispatchConfig{
		Service: &DispatchService{Port: 3000},
	})
	assert.Contains(t, spec.Ports, 3000)
	assert.Equal(t, types.WorkloadKindService, spec.DetectedKind)
}

func TestApplyConfig_ServiceNoDuplicate(t *testing.T) {
	spec := &types.WorkloadSpec{Ports: []int{3000}}
	ApplyConfig(spec, &DispatchConfig{
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
	ApplyConfig(spec, &DispatchConfig{Sandbox: true})
	assert.Equal(t, types.WorkloadKindSandbox, spec.DetectedKind)
}

func TestApplyConfig_Nil(t *testing.T) {
	spec := &types.WorkloadSpec{Name: "original"}
	ApplyConfig(spec, nil)
	assert.Equal(t, "original", spec.Name)
}

func TestInspectCodebase_WithDispatchYaml(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hello")`)
	writeFile(t, dir, "dispatch.yaml", `
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
	writeFile(t, dir, "dispatch.yaml", `
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
