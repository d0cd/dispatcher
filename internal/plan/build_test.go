package plan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuild_PythonScript(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hello")`)
	writeFile(t, dir, "requirements.txt", "requests\n")

	p, err := Build(dir, types.PlanConstraints{
		OptimizeFor: types.OptimizeCost,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, p.Recommendation)

	assert.Equal(t, "dispatcher.dev/v1", p.APIVersion)
	assert.Equal(t, "Plan", p.Kind)
	assert.Equal(t, types.WorkloadKindScript, p.Workload.DetectedKind)
	assert.Equal(t, types.RuntimePython, p.Workload.Runtime)

	// Should recommend local-process (cheapest, no container overhead)
	assert.Equal(t, "local-process", p.Recommendation.Target)
	assert.Equal(t, 0.0, p.Recommendation.EstimatedCost.Value)

	// Should have alternatives
	assert.NotEmpty(t, p.Alternatives)

	// Validation should pass
	assert.True(t, p.Validation.IsValid())
}

func TestBuild_MergesRegionFromConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hi")`)
	writeFile(t, dir, "dispatcher.yaml", "name: app\nregion: eu-west-1\n")

	// No --region flag → the config value fills the constraint.
	p, err := Build(dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost}, nil)
	require.NoError(t, err)
	assert.Equal(t, "eu-west-1", p.Constraints.Region)

	// A flag-provided region wins over config.
	p2, err := Build(dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost, Region: "us-east-2"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "us-east-2", p2.Constraints.Region)
}

func TestBuild_DockerizedService(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM python:3.11\nEXPOSE 8080\nCMD [\"python\", \"app.py\"]")
	writeFile(t, dir, "app.py", "from flask import Flask\napp = Flask(__name__)\napp.run(port=8080)")

	p, err := Build(dir, types.PlanConstraints{
		OptimizeFor: types.OptimizeCost,
	}, nil)
	require.NoError(t, err)

	assert.Equal(t, types.WorkloadKindService, p.Workload.DetectedKind)
	assert.Contains(t, p.Workload.Ports, 8080)
	assert.NotNil(t, p.Recommendation)

}

func TestBuild_GPUJob(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "torch\nnumpy\n")
	writeFile(t, dir, "train.py", "import torch")

	p, err := Build(dir, types.PlanConstraints{
		OptimizeFor: types.OptimizeCost,
	}, nil)
	require.NoError(t, err)

	assert.Equal(t, types.WorkloadKindGPUJob, p.Workload.DetectedKind)
	assert.True(t, p.Workload.Requirements.GPU.Required)

	// CPU-only targets should be rejected
	rejectedTargets := make([]string, len(p.Rejected))
	for i, r := range p.Rejected {
		rejectedTargets[i] = r.Target
	}
	assert.Contains(t, rejectedTargets, "local-docker")

	// Should require GPU approval
	approvalNames := make([]string, len(p.RequiredApprovals))
	for i, a := range p.RequiredApprovals {
		approvalNames[i] = a.Name
	}
	assert.Contains(t, approvalNames, "gpu-approval")
}

func TestBuild_SpecificTarget(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM python:3.11\nCMD [\"python\", \"main.py\"]")
	writeFile(t, dir, "main.py", `print("hello")`)

	p, err := Build(dir, types.PlanConstraints{
		OptimizeFor: types.OptimizeCost,
		TargetName:  "kubernetes",
	}, nil)
	require.NoError(t, err)

	assert.Equal(t, "kubernetes", p.Recommendation.Target)
}

func TestBuild_SpecificTargetNotFound(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hello")`)

	_, err := Build(dir, types.PlanConstraints{
		TargetName: "nonexistent",
	}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestBuild_MaxCostFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM python:3.11\nEXPOSE 8080")
	writeFile(t, dir, "app.py", "app.run(port=8080)")

	p, err := Build(dir, types.PlanConstraints{
		OptimizeFor:         types.OptimizeCost,
		MaxEstimatedCostUSD: 1.0,
	}, nil)
	require.NoError(t, err)

	// All recommended/alternative costs should be within budget
	assert.LessOrEqual(t, p.Recommendation.EstimatedCost.Value, 1.0)
	for _, alt := range p.Alternatives {
		assert.LessOrEqual(t, alt.EstimatedCost.Value, 1.0)
	}
}

func TestBuild_OptimizeSpeed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hello")`)

	p, err := Build(dir, types.PlanConstraints{
		OptimizeFor: types.OptimizeSpeed,
	}, nil)
	require.NoError(t, err)

	// Should prefer local targets for speed
	assert.Contains(t, []string{"local-process", "local-docker"}, p.Recommendation.Target)
}

func TestBuild_ExecutionSteps(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM python:3.11\nEXPOSE 8080")
	writeFile(t, dir, "app.py", "app.run(port=8080)")

	p, err := Build(dir, types.PlanConstraints{
		OptimizeFor: types.OptimizeCost,
	}, nil)
	require.NoError(t, err)

	assert.Contains(t, p.ExecutionSteps, "build-image")
	assert.Contains(t, p.ExecutionSteps, "stream-logs")
	assert.Contains(t, p.ExecutionSteps, "register-cleanup")
}

func TestApplyGPUOverride(t *testing.T) {
	invalid := []string{"h100:abc", "h100:0", "0"}
	for _, gpu := range invalid {
		t.Run("invalid/"+gpu, func(t *testing.T) {
			var spec types.WorkloadSpec
			err := applyGPUOverride(&spec, gpu)
			assert.Error(t, err)
		})
	}

	valid := []struct {
		gpu   string
		count int
		model string
	}{
		{"h100:2", 2, "h100"},
		{"2", 2, ""},
		{"h100:1", 1, "h100"},
	}
	for _, tc := range valid {
		t.Run("valid/"+tc.gpu, func(t *testing.T) {
			var spec types.WorkloadSpec
			err := applyGPUOverride(&spec, tc.gpu)
			require.NoError(t, err)
			assert.Equal(t, tc.count, spec.Requirements.GPU.Count)
			assert.Equal(t, tc.model, spec.Requirements.GPU.Model)
		})
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	// Support nested paths
	full := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
}
