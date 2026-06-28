package planner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeRunFixture writes a serialized run record + optional log file into the
// state directory. Mirrors the on-disk shape produced by run.Run.Save().
func writeRunFixture(t *testing.T, runID, state, errMsg string, logBody string) {
	t.Helper()
	stateRoot := os.Getenv("DISPATCHER_HOME")
	if stateRoot == "" {
		// Fall back to $HOME/.dispatcher when no override is set; the test
		// caller is expected to have pinned $HOME via t.TempDir().
		stateRoot = filepath.Join(os.Getenv("HOME"), ".dispatcher")
	}
	runsDir := filepath.Join(stateRoot, "runs")
	require.NoError(t, os.MkdirAll(runsDir, 0o700))

	logPath := ""
	if logBody != "" {
		logPath = filepath.Join(runsDir, runID+".log")
		require.NoError(t, os.WriteFile(logPath, []byte(logBody), 0o600))
	}

	rec := map[string]any{
		"id":       runID,
		"planId":   "plan_test",
		"targetId": "local-process",
		"state":    state,
		"error":    errMsg,
		"cost": map[string]any{
			"value":      0.0,
			"currency":   "USD",
			"confidence": "medium",
		},
		"logFile": logPath,
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(runsDir, runID+".json"), data, 0o600))
}

func TestToolRegistry_InspectRun_Basic(t *testing.T) {
	tools, _ := setupTestEnv(t)

	writeRunFixture(t, "run_diag1", "execution-failed",
		"workload exited with code 1",
		"line one\nline two\nline three\n")

	result := tools.Execute(ToolCall{
		Name:  "inspect_run",
		Input: mustJSON(map[string]any{"run_id": "run_diag1"}),
	}, nil)

	require.Empty(t, result.Error)
	insp, ok := result.Result.(RunInspection)
	require.True(t, ok)

	assert.Equal(t, "run_diag1", insp.ID)
	assert.Equal(t, types.RunState("execution-failed"), insp.State)
	assert.Equal(t, "workload exited with code 1", insp.Error)
	assert.Equal(t, []string{"line one", "line two", "line three"}, insp.LogTail)
	assert.False(t, insp.LogTruncated)
}

func TestToolRegistry_InspectRun_LogTruncation(t *testing.T) {
	tools, _ := setupTestEnv(t)

	var body string
	for i := 0; i < 100; i++ {
		body += "line\n"
	}
	writeRunFixture(t, "run_diag2", "completed", "", body)

	result := tools.Execute(ToolCall{
		Name:  "inspect_run",
		Input: mustJSON(map[string]any{"run_id": "run_diag2", "log_lines": 10}),
	}, nil)

	require.Empty(t, result.Error)
	insp := result.Result.(RunInspection)
	assert.Len(t, insp.LogTail, 10)
	assert.True(t, insp.LogTruncated)
}

func TestToolRegistry_InspectRun_MissingRun(t *testing.T) {
	tools, _ := setupTestEnv(t)

	result := tools.Execute(ToolCall{
		Name:  "inspect_run",
		Input: mustJSON(map[string]any{"run_id": "run_nope"}),
	}, nil)
	assert.NotEmpty(t, result.Error)
}

func TestToolRegistry_InspectRun_MissingID(t *testing.T) {
	tools, _ := setupTestEnv(t)

	result := tools.Execute(ToolCall{
		Name:  "inspect_run",
		Input: mustJSON(map[string]any{"run_id": ""}),
	}, nil)
	assert.NotEmpty(t, result.Error)
	assert.Contains(t, result.Error, "required")
}

func TestDeterministicDiagnose_FailedRun(t *testing.T) {
	tools, _ := setupTestEnv(t)
	writeRunFixture(t, "run_diag3", "execution-failed",
		"workload exited with code 1",
		"ModuleNotFoundError: No module named 'numpy'\n")

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicDiagnose(context.Background(), "run_diag3")
	require.NoError(t, err)

	assert.Equal(t, "error", res.Severity)
	assert.Contains(t, res.Explanation, "run_diag3")
	assert.Contains(t, res.Explanation, "execution-failed")
	assert.Contains(t, res.LikelyCause, "workload exited")
	assert.Contains(t, res.Recommendation, "log tail")
	assert.Equal(t, []string{"inspect_run"}, res.ToolsUsed)
}

func TestDeterministicDiagnose_BudgetExceeded(t *testing.T) {
	tools, _ := setupTestEnv(t)
	writeRunFixture(t, "run_diag4", "budget-exceeded", "", "")

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicDiagnose(context.Background(), "run_diag4")
	require.NoError(t, err)

	assert.Equal(t, "warning", res.Severity)
	assert.Contains(t, res.LikelyCause, "budget")
	assert.Contains(t, res.Recommendation, "--max-cost")
}

func TestDeterministicDiagnose_CompletedRun(t *testing.T) {
	tools, _ := setupTestEnv(t)
	writeRunFixture(t, "run_diag5", "completed", "", "")

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicDiagnose(context.Background(), "run_diag5")
	require.NoError(t, err)

	assert.Equal(t, "info", res.Severity)
	assert.Contains(t, res.Recommendation, "No action")
}

func TestDeterministicDiagnose_MissingRun(t *testing.T) {
	tools, _ := setupTestEnv(t)

	p := NewPlanner(nil, tools)
	_, err := p.DeterministicDiagnose(context.Background(), "run_nope")
	assert.Error(t, err)
}

// writeRunFixtureWithHandleState writes a run record carrying adapter
// HandleState, used to test attestation surfacing in diagnose.
func writeRunFixtureWithHandleState(t *testing.T, runID, state, handleState string) {
	t.Helper()
	stateRoot := os.Getenv("DISPATCHER_HOME")
	if stateRoot == "" {
		stateRoot = filepath.Join(os.Getenv("HOME"), ".dispatcher")
	}
	runsDir := filepath.Join(stateRoot, "runs")
	require.NoError(t, os.MkdirAll(runsDir, 0o700))

	rec := map[string]any{
		"id":       runID,
		"planId":   "plan_test",
		"targetId": "gcp-vm",
		"state":    state,
		"cost": map[string]any{
			"value": 0.0, "currency": "USD", "confidence": "medium",
		},
		"handleState": json.RawMessage(handleState),
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(runsDir, runID+".json"), data, 0o600))
}

func TestDeterministicDiagnose_SurfacesAttestation(t *testing.T) {
	tools, _ := setupTestEnv(t)
	writeRunFixtureWithHandleState(t, "run_att", "completed",
		`{"attestation":{"verified":true,"type":"sev-snp","measurement":"abcd"}}`)

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicDiagnose(context.Background(), "run_att")
	require.NoError(t, err)
	assert.Contains(t, res.Explanation, "attestation")
	assert.Contains(t, res.Explanation, "sev-snp")
}

// writeRunFixtureWithFailure writes a serialized run record with full
// failure detail so we can test the diagnostic surfacing path.
func writeRunFixtureWithFailure(t *testing.T, runID string, exitCode int, signal string, oomKilled bool) {
	t.Helper()
	stateRoot := os.Getenv("DISPATCHER_HOME")
	if stateRoot == "" {
		stateRoot = filepath.Join(os.Getenv("HOME"), ".dispatcher")
	}
	runsDir := filepath.Join(stateRoot, "runs")
	require.NoError(t, os.MkdirAll(runsDir, 0o700))

	rec := map[string]any{
		"id":       runID,
		"planId":   "plan_test",
		"targetId": "local-docker",
		"state":    "execution-failed",
		"cost": map[string]any{
			"value": 0.0, "currency": "USD", "confidence": "medium",
		},
		"failure": map[string]any{
			"ExitCode":  exitCode,
			"Signal":    signal,
			"OOMKilled": oomKilled,
		},
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(runsDir, runID+".json"), data, 0o600))
}

func TestDeterministicDiagnose_OOMKillSuggestsRetry(t *testing.T) {
	tools, _ := setupTestEnv(t)
	writeRunFixtureWithFailure(t, "run_oom1", 137, "SIGKILL", true)

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicDiagnose(context.Background(), "run_oom1")
	require.NoError(t, err)

	assert.Contains(t, res.LikelyCause, "out-of-memory")
	assert.Contains(t, res.Recommendation, "retryTransientFailures",
		"OOM should mention the retry knob, not just 'fix the workload'")
}

func TestDeterministicDiagnose_NonZeroExitSuggestsFix(t *testing.T) {
	tools, _ := setupTestEnv(t)
	writeRunFixtureWithFailure(t, "run_bug1", 1, "", false)

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicDiagnose(context.Background(), "run_bug1")
	require.NoError(t, err)

	// Exit code 1 with no signal classifies permanent — no retry suggestion.
	assert.Contains(t, res.LikelyCause, "exited with code 1")
	assert.NotContains(t, res.Recommendation, "retryTransientFailures")
	assert.Contains(t, res.Recommendation, "log tail")
}
