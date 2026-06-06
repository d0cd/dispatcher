package planner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/target"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestEnv(t *testing.T) (*ToolRegistry, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())

	reg := target.NewRegistry()
	reg.LoadBuiltins()

	hist, _ := cost.NewHistoryStore()
	cat := cloudvm.NewCatalog()

	tools := NewToolRegistry(reg, hist, cat)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`print("hello")`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask\n"), 0o644))

	return tools, dir
}

func TestToolRegistry_InspectWorkload(t *testing.T) {
	tools, dir := setupTestEnv(t)

	result := tools.Execute(ToolCall{
		Name:  "inspect_workload",
		Input: mustJSON(map[string]string{"path": dir}),
	}, nil)

	assert.Empty(t, result.Error)
	spec, ok := result.Result.(types.WorkloadSpec)
	assert.True(t, ok)
	assert.Equal(t, types.RuntimePython, spec.Runtime)
}

func TestToolRegistry_EvaluateAllTargets(t *testing.T) {
	tools, dir := setupTestEnv(t)

	// First inspect
	inspectResult := tools.Execute(ToolCall{
		Name:  "inspect_workload",
		Input: mustJSON(map[string]string{"path": dir}),
	}, nil)
	spec := inspectResult.Result.(types.WorkloadSpec)

	// Then evaluate all
	result := tools.Execute(ToolCall{
		Name:  "evaluate_all_targets",
		Input: json.RawMessage("{}"),
	}, &spec)

	assert.Empty(t, result.Error)
	evals, ok := result.Result.([]TargetEvaluation)
	assert.True(t, ok)
	assert.GreaterOrEqual(t, len(evals), 7)

	// local-process should be feasible for a python script
	var localEval *TargetEvaluation
	for i, e := range evals {
		if e.TargetID == "local-process" {
			localEval = &evals[i]
			break
		}
	}
	require.NotNil(t, localEval)
	assert.True(t, localEval.Feasible)
	assert.NotNil(t, localEval.Cost)
}

func TestToolRegistry_EvaluateAllTargets_NilSpec(t *testing.T) {
	tools, _ := setupTestEnv(t)

	result := tools.Execute(ToolCall{
		Name:  "evaluate_all_targets",
		Input: json.RawMessage("{}"),
	}, nil)

	assert.Contains(t, result.Error, "inspect_workload first")
}

func TestToolRegistry_FindInstances(t *testing.T) {
	tools, _ := setupTestEnv(t)

	result := tools.Execute(ToolCall{
		Name:  "find_cheapest_instances",
		Input: mustJSON(map[string]any{"min_vcpus": 2, "min_memory_gb": 4}),
	}, nil)

	assert.Empty(t, result.Error)
	instances, ok := result.Result.([]cloudvm.InstanceType)
	assert.True(t, ok)
	assert.NotEmpty(t, instances)
	assert.LessOrEqual(t, len(instances), 10)
}

func TestToolRegistry_FindInstances_GPU(t *testing.T) {
	tools, _ := setupTestEnv(t)

	result := tools.Execute(ToolCall{
		Name:  "find_cheapest_instances",
		Input: mustJSON(map[string]any{"gpu_count": 1, "gpu_model": "a100"}),
	}, nil)

	assert.Empty(t, result.Error)
	instances := result.Result.([]cloudvm.InstanceType)
	for _, inst := range instances {
		assert.Equal(t, "a100", inst.GPUModel)
	}
}

func TestToolRegistry_GetHistory(t *testing.T) {
	tools, _ := setupTestEnv(t)

	result := tools.Execute(ToolCall{
		Name:  "get_run_history",
		Input: mustJSON(map[string]string{"target_id": "local-process"}),
	}, nil)

	assert.Empty(t, result.Error)
}

func TestToolRegistry_UnknownTool(t *testing.T) {
	tools, _ := setupTestEnv(t)

	result := tools.Execute(ToolCall{Name: "nonexistent"}, nil)
	assert.Contains(t, result.Error, "unknown tool")
}

func TestToolDefinitions(t *testing.T) {
	tools, _ := setupTestEnv(t)
	defs := tools.Definitions()

	assert.Len(t, defs, 4)
	names := make([]string, len(defs))
	for i, d := range defs {
		names[i] = d.Name
		assert.NotEmpty(t, d.Description)
		assert.NotNil(t, d.Parameters)
	}
	assert.Contains(t, names, "inspect_workload")
	assert.Contains(t, names, "evaluate_all_targets")
	assert.Contains(t, names, "find_cheapest_instances")
	assert.Contains(t, names, "get_run_history")
}

func TestDeterministicPlan_PythonScript(t *testing.T) {
	tools, dir := setupTestEnv(t)
	planner := NewPlanner(nil, tools)

	result, err := planner.DeterministicPlan(
		context.Background(), dir,
		types.PlanConstraints{OptimizeFor: types.OptimizeCost},
	)
	require.NoError(t, err)
	require.NotNil(t, result.Recommendation)

	assert.Equal(t, "local-process", result.Recommendation.Target)
	assert.NotEmpty(t, result.Explanation)
	assert.Contains(t, result.ToolsUsed, "inspect_workload")
	assert.Contains(t, result.ToolsUsed, "evaluate_all_targets")
}

func TestDeterministicPlan_WithBudget(t *testing.T) {
	tools, dir := setupTestEnv(t)
	planner := NewPlanner(nil, tools)

	result, err := planner.DeterministicPlan(
		context.Background(), dir,
		types.PlanConstraints{
			OptimizeFor:         types.OptimizeCost,
			MaxEstimatedCostUSD: 0.01,
		},
	)
	require.NoError(t, err)

	if result.Recommendation != nil {
		assert.LessOrEqual(t, result.Recommendation.EstimatedCost.Value, 0.01)
	}
	assert.NotEmpty(t, result.Rejected)
}

func TestDeterministicPlan_GPUWorkload(t *testing.T) {
	tools, _ := setupTestEnv(t)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "train.py"), []byte("import torch"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("torch\n"), 0o644))

	planner := NewPlanner(nil, tools)
	result, err := planner.DeterministicPlan(
		context.Background(), dir,
		types.PlanConstraints{OptimizeFor: types.OptimizeCost},
	)
	require.NoError(t, err)

	rejectedNames := make([]string, len(result.Rejected))
	for i, r := range result.Rejected {
		rejectedNames[i] = r.Target
	}
	assert.Contains(t, rejectedNames, "local-process")
	assert.Contains(t, rejectedNames, "local-docker")
}

// mockBackend simulates an LLM that inspects then evaluates then responds.
type mockBackend struct {
	calls int
}

func (m *mockBackend) Chat(_ context.Context, messages []Message, _ []Tool) (*Message, error) {
	m.calls++
	if m.calls == 1 {
		return &Message{
			Role: "assistant",
			ToolCalls: []ToolCall{
				{Name: "inspect_workload", Input: mustJSON(map[string]string{"path": "/tmp/test"})},
			},
		}, nil
	}
	if m.calls == 2 {
		return &Message{
			Role: "assistant",
			ToolCalls: []ToolCall{
				{Name: "evaluate_all_targets", Input: json.RawMessage("{}")},
			},
		}, nil
	}
	return &Message{
		Role:    "assistant",
		Content: "I recommend local-process. It's free, fast, and your Python script has no special requirements.",
	}, nil
}

func TestPlanner_WithMockBackend(t *testing.T) {
	tools, _ := setupTestEnv(t)
	backend := &mockBackend{}
	planner := NewPlanner(backend, tools)

	result, err := planner.Plan(
		context.Background(), "/tmp/test",
		types.PlanConstraints{},
	)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Explanation)
	assert.Contains(t, result.Explanation, "local-process")
	assert.Contains(t, result.ToolsUsed, "inspect_workload")
	assert.Contains(t, result.ToolsUsed, "evaluate_all_targets")
	assert.Equal(t, 3, backend.calls)
}

// agentBackend simulates a one-shot agentic backend (like AtelierBackend) that
// returns the final result as a single JSON message matching dispatcher's types.
type agentBackend struct{}

func (a *agentBackend) Chat(_ context.Context, _ []Message, _ []Tool) (*Message, error) {
	payload := `{
        "explanation": "Use local-process for this Python script.",
        "recommendation": {
            "target": "local-process",
            "runtime": "python3",
            "estimatedCost": {"value": 0, "currency": "USD", "confidence": "high"},
            "reason": ["Free", "No GPU needed"]
        },
        "alternatives": [
            {"target": "local-docker", "runtime": "docker", "estimatedCost": {"value": 0, "currency": "USD", "confidence": "high"}, "tradeoff": ["Container isolation"]}
        ],
        "rejected": [{"target": "kubernetes", "reason": "script kind not supported"}],
        "risks": [{"category": "package-risk", "description": "No Dockerfile present"}],
        "approvals": [{"name": "budget", "reason": "over $25 threshold"}],
        "suggestions": ["Add a Dockerfile"],
        "toolsUsed": ["inspect_workload", "evaluate_all_targets"]
    }`
	return &Message{Role: "assistant", Content: payload}, nil
}

func TestPlanner_AgentStructuredOutputPopulatesTypedFields(t *testing.T) {
	tools, _ := setupTestEnv(t)
	p := NewPlanner(&agentBackend{}, tools)

	result, err := p.Plan(context.Background(), "/tmp/test", types.PlanConstraints{})
	require.NoError(t, err)

	require.NotNil(t, result.Recommendation)
	assert.Equal(t, "local-process", result.Recommendation.Target)
	assert.Equal(t, "python3", result.Recommendation.Runtime)
	assert.Equal(t, 0.0, result.Recommendation.EstimatedCost.Value)
	assert.Equal(t, types.ConfidenceHigh, result.Recommendation.EstimatedCost.Confidence)
	assert.Contains(t, result.Recommendation.Reason, "Free")

	require.Len(t, result.Alternatives, 1)
	assert.Equal(t, "local-docker", result.Alternatives[0].Target)

	require.Len(t, result.Rejected, 1)
	assert.Equal(t, "kubernetes", result.Rejected[0].Target)

	require.Len(t, result.Risks, 1)
	assert.Equal(t, "package-risk", result.Risks[0].Category)

	require.Len(t, result.Approvals, 1)
	assert.Equal(t, "budget", result.Approvals[0].Name)

	assert.Equal(t, []string{"Add a Dockerfile"}, result.Suggestions)

	// Explanation should be the prose, not the JSON dump
	assert.Equal(t, "Use local-process for this Python script.", result.Explanation)
	assert.NotContains(t, result.Explanation, "{")

	// ToolsUsed should reflect what the agent reported
	assert.Contains(t, result.ToolsUsed, "inspect_workload")
	assert.Contains(t, result.ToolsUsed, "evaluate_all_targets")
}

// Tool names reported by claude-code carry the MCP namespace prefix; the
// planner strips it so reported names match dispatcher's native tool names.
type prefixedAgentBackend struct{}

func (p *prefixedAgentBackend) Chat(_ context.Context, _ []Message, _ []Tool) (*Message, error) {
	return &Message{Role: "assistant", Content: `{
        "explanation": "ok",
        "toolsUsed": ["mcp__dispatcher__inspect_workload", "mcp__dispatcher__evaluate_all_targets"]
    }`}, nil
}

func TestPlanner_StripsMCPNamespaceFromToolsUsed(t *testing.T) {
	tools, _ := setupTestEnv(t)
	p := NewPlanner(&prefixedAgentBackend{}, tools)
	result, err := p.Plan(context.Background(), "/tmp/test", types.PlanConstraints{})
	require.NoError(t, err)
	assert.Equal(t, []string{"inspect_workload", "evaluate_all_targets"}, result.ToolsUsed)
}

// proseBackend returns plain prose (not JSON) — the parser should leave fields nil
// and preserve the prose as Explanation.
type proseBackend struct{}

func (p *proseBackend) Chat(_ context.Context, _ []Message, _ []Tool) (*Message, error) {
	return &Message{Role: "assistant", Content: "I recommend local-process because it is free."}, nil
}

func TestPlanner_ProseBackendKeepsExplanationOnly(t *testing.T) {
	tools, _ := setupTestEnv(t)
	p := NewPlanner(&proseBackend{}, tools)

	result, err := p.Plan(context.Background(), "/tmp/test", types.PlanConstraints{})
	require.NoError(t, err)

	assert.Contains(t, result.Explanation, "local-process")
	assert.Nil(t, result.Recommendation)
	assert.Empty(t, result.Alternatives)
}
