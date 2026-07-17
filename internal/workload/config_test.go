package workload

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestApplyConfig_Confidential(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatcherConfig{Confidential: &DispatchConfidentialConfig{Type: "sev-snp"}})
	assert.True(t, spec.Requirements.Confidential.Required)
	assert.Equal(t, "sev-snp", spec.Requirements.Confidential.Type)
	assert.Equal(t, "required", spec.Requirements.Confidential.Attestation, "attestation defaults to required")
}

func TestApplyConfig_Shard(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatcherConfig{
		Shard:     &DispatchShardConfig{Count: 8, Discover: "pytest --collect-only -q", MaxParallel: 4},
		Aggregate: &DispatchAggregateConfig{Outputs: []string{"results/"}, OnShardFailure: "continue"},
	})
	assert.True(t, spec.Shard.Enabled())
	assert.Equal(t, 8, spec.Shard.Count)
	assert.Equal(t, "pytest --collect-only -q", spec.Shard.Discover)
	assert.Equal(t, 4, spec.Shard.MaxParallel)
	assert.Equal(t, []string{"results/"}, spec.Shard.Outputs)
	assert.Equal(t, []string{"results/"}, spec.Outputs,
		"aggregate outputs must be collected by each shard adapter")
	assert.Equal(t, "continue", spec.Shard.OnShardFailure)
}

func TestApplyConfig_AggregateOutputsAreSanitizedAndMerged(t *testing.T) {
	spec := &types.WorkloadSpec{Outputs: []string{"existing/"}}
	ApplyConfig(spec, &DispatcherConfig{
		Outputs:   []string{"top-level/", "existing/"},
		Aggregate: &DispatchAggregateConfig{Outputs: []string{"shards/", "../private"}},
	})
	assert.Equal(t, []string{"shards/"}, spec.Shard.Outputs)
	assert.Equal(t, []string{"top-level/", "existing/", "shards/"}, spec.Outputs)
}

func TestLoadConfig_ParsesShard(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", "name: app\nshard:\n  count: 20\n")
	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg.Shard)
	assert.Equal(t, 20, cfg.Shard.Count)
}

func TestConfig_RejectsBadOnShardFailure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", "name: x\naggregate:\n  onShardFailure: explode\n")
	_, err := LoadConfig(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "onShardFailure")
}

func TestConfig_RejectsNegativeShardCount(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", "name: x\nshard:\n  count: -3\n")
	_, err := LoadConfig(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "count")
}

func TestLoadConfig_ParsesRegion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", "name: app\nregion: eu-west-1\n")
	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	assert.Equal(t, "eu-west-1", cfg.Region)
}

func TestLoadConfig_ExpandsEnvVars(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DISPATCHER_TEST_TARGET", "gcp-vm")
	writeFile(t, dir, "dispatcher.yaml",
		"name: ${DISPATCHER_TEST_NAME:-fallback-app}\ntarget: ${DISPATCHER_TEST_TARGET}\n")
	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	assert.Equal(t, "gcp-vm", cfg.Target, "a set var is substituted")
	assert.Equal(t, "fallback-app", cfg.Name, "an unset var falls back to its :- default")
}

// A ${VAR} whose value contains a newline must be rejected, not substituted into
// the raw pre-parse bytes where it would inject an extra top-level YAML key (e.g.
// silently raising a cost cap).
func TestLoadConfig_RejectsEnvValueWithNewline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DISPATCHER_TEST_REGION", "us-east-1\nmaxCost: 100000")
	writeFile(t, dir, "dispatcher.yaml", "name: app\nregion: ${DISPATCHER_TEST_REGION}\n")
	_, err := LoadConfig(dir)
	require.Error(t, err, "an env value with a line break must be refused, not injected")
	assert.Contains(t, err.Error(), "line break")
}

func TestLoadConfig_UndefinedEnvVarErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", "name: ${DISPATCHER_TEST_UNSET_XYZ}\n")
	_, err := LoadConfig(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DISPATCHER_TEST_UNSET_XYZ", "an undefined ${VAR} with no default fails loudly")
}

func TestLoadConfig_LeavesBareDollarUntouched(t *testing.T) {
	dir := t.TempDir()
	// A bare $VAR (common in a shell command meant for remote expansion) must
	// NOT be expanded — only the explicit ${...} form is.
	writeFile(t, dir, "dispatcher.yaml", "name: app\ncommand: [\"sh\", \"-c\", \"echo $HOME\"]\n")
	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	assert.Equal(t, []string{"sh", "-c", "echo $HOME"}, cfg.Command)
}

func TestApplyConfig_ConfidentialMeasurementsAndTCB(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatcherConfig{Confidential: &DispatchConfidentialConfig{
		Type:         "sev-snp",
		Measurements: []string{"ab12", "cd34"},
		MinTCB:       7,
	}})
	assert.Equal(t, []string{"ab12", "cd34"}, spec.Requirements.Confidential.Measurements,
		"the exact measurement allowlist must reach the verifier (R7)")
	assert.Equal(t, uint64(7), spec.Requirements.Confidential.MinTCB)
}

func TestLoadConfig_ParsesConfidentialMeasurements(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml",
		"name: secure\nconfidential:\n  type: sev-snp\n  measurements:\n    - deadbeef\n  minTCB: 5\n")
	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg.Confidential)
	assert.Equal(t, []string{"deadbeef"}, cfg.Confidential.Measurements)
	assert.Equal(t, uint64(5), cfg.Confidential.MinTCB)
}

func TestApplyConfig_ConfidentialAttestationOff(t *testing.T) {
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, &DispatcherConfig{Confidential: &DispatchConfidentialConfig{Attestation: "off"}})
	assert.True(t, spec.Requirements.Confidential.Required)
	assert.Equal(t, "off", spec.Requirements.Confidential.Attestation)
}

func TestLoadConfig_ParsesConfidential(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", "name: secure\nconfidential:\n  type: tdx\n  attestation: required\n")
	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Confidential)
	assert.Equal(t, "tdx", cfg.Confidential.Type)
}

func TestConfig_RejectsBadConfidentialType(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", "name: x\nconfidential:\n  type: bogus\n")
	_, err := LoadConfig(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "confidential.type")
}

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

func TestLoadConfig_RetryTransientFailures(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", "name: my-app\nretryTransientFailures: true\n")

	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.RetryTransientFailures)
	assert.True(t, *cfg.RetryTransientFailures)
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
	assert.Equal(t, types.WorkloadKindScript, spec.DetectedKind,
		"an explicit command is an executable script workload even without detectable source")
}

func TestLoadAndApplyConfig_ResourceConstraints(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dispatcher.yaml", "name: compute\ncpu: 16\nmemory: 30G\narch: x86_64\n")

	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	spec := &types.WorkloadSpec{}
	ApplyConfig(spec, cfg)

	assert.Equal(t, "16", spec.Requirements.CPU)
	assert.Equal(t, "30G", spec.Requirements.Memory)
	assert.Equal(t, "x86_64", spec.Requirements.Arch)
}

func TestConfig_RejectsInvalidResourceConstraints(t *testing.T) {
	for name, body := range map[string]string{
		"cpu":    "cpu: zero\n",
		"memory": "memory: lots\n",
		"arch":   "arch: sparc\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "dispatcher.yaml", "name: bad\n"+body)
			_, err := LoadConfig(dir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
		})
	}
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

// sandbox is an isolation requirement, not a workload kind: it must set the
// Sandbox requirement (so feasibility can gate process-only targets) while
// leaving the detected kind intact — otherwise a sandboxed script would be
// misclassified and mis-planned.
func TestApplyConfig_Sandbox(t *testing.T) {
	spec := &types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	ApplyConfig(spec, &DispatcherConfig{Sandbox: true})
	assert.Equal(t, types.WorkloadKindScript, spec.DetectedKind, "sandbox must not overwrite the detected kind")
	assert.True(t, spec.Requirements.Sandbox, "sandbox must set the isolation requirement")
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
