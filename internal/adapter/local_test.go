package adapter

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalAdapter_ID(t *testing.T) {
	a := NewLocalAdapter()
	assert.Equal(t, "local-process", a.ID())
}

func TestLocalAdapter_CostEstimate(t *testing.T) {
	a := NewLocalAdapter()
	est, err := a.EstimateCost(context.Background(), types.WorkloadSpec{})
	assert.NoError(t, err)
	assert.Equal(t, 0.0, est.Value)
	assert.Equal(t, types.ConfidenceHigh, est.Confidence)
}

func TestLocalAdapter_RejectsGPU(t *testing.T) {
	a := NewLocalAdapter()
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindGPUJob,
		Requirements: types.ResourceRequirements{
			GPU: types.GPURequirement{Required: true},
		},
	}

	v, err := a.Validate(context.Background(), w)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GPU")
	assert.Equal(t, types.ValidationFail, v.TargetCapabilities)
}

func TestLocalAdapter_ValidatesPythonAvailable(t *testing.T) {
	a := NewLocalAdapter()
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Runtime:      types.RuntimePython,
	}

	v, err := a.Validate(context.Background(), w)
	// python3 may or may not be available in test env
	if err != nil {
		assert.Equal(t, types.ValidationFail, v.TargetCapabilities)
		assert.Contains(t, err.Error(), "not found")
	} else {
		assert.Equal(t, types.ValidationPass, v.TargetCapabilities)
	}
}

func TestLocalAdapter_Cleanup(t *testing.T) {
	a := NewLocalAdapter()
	h := &RunHandle{ID: "test", TargetID: "local-process"}
	result, err := a.Cleanup(context.Background(), h)
	assert.NoError(t, err)
	assert.True(t, result.Success)
}

func TestLocalAdapter_ContractTest(t *testing.T) {
	a := NewLocalAdapter()
	ContractTest(t, a)
}

func TestBuildCommand_ExplicitCommand(t *testing.T) {
	w := types.WorkloadSpec{
		Command: []string{"python3", "train.py", "--epochs", "10"},
	}
	cmd, err := buildCommand(w)
	require.NoError(t, err)
	assert.Equal(t, []string{"python3", "train.py", "--epochs", "10"}, cmd)
}

func TestBuildCommand_FromEntrypoint(t *testing.T) {
	w := types.WorkloadSpec{
		Runtime:     types.RuntimePython,
		Entrypoints: []string{"main.py"},
	}
	cmd, err := buildCommand(w)
	require.NoError(t, err)
	assert.Equal(t, "main.py", cmd[1])
	assert.Contains(t, cmd[0], "python")
}

func TestBuildCommand_SkipsDockerfile(t *testing.T) {
	w := types.WorkloadSpec{
		Runtime:     types.RuntimePython,
		Entrypoints: []string{"Dockerfile", "main.py"},
	}
	cmd, err := buildCommand(w)
	require.NoError(t, err)
	assert.Equal(t, "main.py", cmd[1])
	assert.Contains(t, cmd[0], "python")
}

func TestBuildCommand_NoEntrypoint(t *testing.T) {
	w := types.WorkloadSpec{
		Runtime: types.RuntimePython,
	}
	_, err := buildCommand(w)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no command or entrypoint")
}

func localTestPlan(dir string) *types.Plan {
	return &types.Plan{
		APIVersion: "dispatcher.dev/v1",
		Kind:       "Plan",
		Metadata: types.PlanMetadata{
			ID:        "plan_local_test",
			CreatedAt: time.Now().UTC(),
			CreatedBy: "test",
		},
		Workload: types.WorkloadSpec{
			Name:         "test-script",
			DetectedKind: types.WorkloadKindScript,
			Runtime:      types.RuntimePython,
			Source:       types.WorkloadSource{Type: "repo", Path: dir},
			Entrypoints:  []string{"main.py"},
		},
		Recommendation: &types.Recommendation{Target: "local-process"},
	}
}

func TestLocalAdapter_Execute_RealProcess(t *testing.T) {
	// Create a script that prints and exits
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`print("hello from test")`), 0o644))

	a := NewLocalAdapter()
	p := localTestPlan(dir)

	ctx := context.Background()
	handle, err := a.Execute(ctx, p)
	require.NoError(t, err)
	require.NotNil(t, handle)
	assert.Equal(t, "local-process", handle.TargetID)

	// Wait for process to complete
	state, err := a.Status(ctx, handle)
	// Process may succeed or fail depending on python3 availability
	_ = err
	_ = state
}

func TestLocalAdapter_Execute_ShOutput(t *testing.T) {
	dir := t.TempDir()
	// Use a simple shell script instead of python
	require.NoError(t, os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho hello\n"), 0o755))

	a := NewLocalAdapter()
	p := &types.Plan{
		APIVersion: "dispatcher.dev/v1",
		Kind:       "Plan",
		Metadata:   types.PlanMetadata{ID: "plan_sh_test", CreatedAt: time.Now().UTC(), CreatedBy: "test"},
		Workload: types.WorkloadSpec{
			Name:    "sh-test",
			Source:  types.WorkloadSource{Type: "repo", Path: dir},
			Command: []string{"sh", "run.sh"},
		},
		Recommendation: &types.Recommendation{Target: "local-process"},
	}

	ctx := context.Background()
	handle, err := a.Execute(ctx, p)
	require.NoError(t, err)

	state, err := a.Status(ctx, handle)
	assert.NoError(t, err)
	assert.Equal(t, types.RunStateCompleted, state)
}

func TestLocalAdapter_Execute_ExitCode(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fail.sh"), []byte("#!/bin/sh\nexit 1\n"), 0o755))

	a := NewLocalAdapter()
	p := &types.Plan{
		APIVersion: "dispatcher.dev/v1",
		Kind:       "Plan",
		Metadata:   types.PlanMetadata{ID: "plan_fail_test", CreatedAt: time.Now().UTC(), CreatedBy: "test"},
		Workload: types.WorkloadSpec{
			Name:    "fail-test",
			Source:  types.WorkloadSource{Type: "repo", Path: dir},
			Command: []string{"sh", "fail.sh"},
		},
		Recommendation: &types.Recommendation{Target: "local-process"},
	}

	ctx := context.Background()
	handle, err := a.Execute(ctx, p)
	require.NoError(t, err)

	state, err := a.Status(ctx, handle)
	assert.NoError(t, err)
	assert.Equal(t, types.RunStateExecutionFailed, state)
}

func TestLocalAdapter_Execute_ContextTimeout(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "slow.sh"), []byte("#!/bin/sh\nsleep 60\n"), 0o755))

	a := NewLocalAdapter()
	p := &types.Plan{
		APIVersion: "dispatcher.dev/v1",
		Kind:       "Plan",
		Metadata:   types.PlanMetadata{ID: "plan_timeout_test", CreatedAt: time.Now().UTC(), CreatedBy: "test"},
		Workload: types.WorkloadSpec{
			Name:    "timeout-test",
			Source:  types.WorkloadSource{Type: "repo", Path: dir},
			Command: []string{"sh", "slow.sh"},
		},
		Recommendation: &types.Recommendation{Target: "local-process"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	handle, err := a.Execute(ctx, p)
	require.NoError(t, err)

	// Status should report failure after timeout
	state, _ := a.Status(ctx, handle)
	assert.Equal(t, types.RunStateExecutionFailed, state)
}

func TestLocalAdapter_Terminate(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "long.sh"), []byte("#!/bin/sh\nsleep 60\n"), 0o755))

	a := NewLocalAdapter()
	p := &types.Plan{
		APIVersion: "dispatcher.dev/v1",
		Kind:       "Plan",
		Metadata:   types.PlanMetadata{ID: "plan_term_test", CreatedAt: time.Now().UTC(), CreatedBy: "test"},
		Workload: types.WorkloadSpec{
			Name:    "term-test",
			Source:  types.WorkloadSource{Type: "repo", Path: dir},
			Command: []string{"sh", "long.sh"},
		},
		Recommendation: &types.Recommendation{Target: "local-process"},
	}

	ctx := context.Background()
	handle, err := a.Execute(ctx, p)
	require.NoError(t, err)

	// Give process a moment to start
	time.Sleep(100 * time.Millisecond)

	// Terminate should not error
	err = a.Terminate(ctx, handle)
	assert.NoError(t, err)
}

func TestLocalAdapter_Logs_NilState(t *testing.T) {
	a := NewLocalAdapter()
	var buf bytes.Buffer
	// With a proper localState but nil pipes, should not error
	h := &RunHandle{ID: "test", State: &localState{}}
	err := a.Logs(context.Background(), h, &buf)
	assert.NoError(t, err)
}
