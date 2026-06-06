package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/d0cd/dispatcher/internal/target"
	"github.com/d0cd/dispatcher/internal/types"
)

// Message represents a conversation message.
type Message struct {
	Role       string      `json:"role"` // "user", "assistant", "tool_result"
	Content    string      `json:"content,omitempty"`
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
	ToolResult *ToolResult `json:"tool_result,omitempty"`

	// ToolsUsed reports tool names already executed upstream (e.g. by an
	// agentic backend). Distinct from ToolCalls, which the planner loop
	// would execute. Setting this lets the planner attribute work without
	// re-running the tools.
	ToolsUsed []string `json:"-"`
}

// Backend is the interface for LLM providers (Claude, OpenAI, local models).
type Backend interface {
	Chat(ctx context.Context, messages []Message, tools []Tool) (*Message, error)
}

// Planner uses an LLM backend with deterministic tools to generate plans.
type Planner struct {
	backend  Backend
	tools    *ToolRegistry
	maxTurns int
}

// NewPlanner creates a planner with the given backend and tools.
func NewPlanner(backend Backend, tools *ToolRegistry) *Planner {
	return &Planner{
		backend:  backend,
		tools:    tools,
		maxTurns: 10,
	}
}

// PlanResult contains the AI planner's output.
type PlanResult struct {
	Explanation    string                    `json:"explanation"`
	Recommendation *types.Recommendation    `json:"recommendation,omitempty"`
	Alternatives   []types.Alternative      `json:"alternatives,omitempty"`
	Rejected       []types.RejectedTarget   `json:"rejected,omitempty"`
	Risks          []types.Risk             `json:"risks,omitempty"`
	Approvals      []types.PolicyRequirement `json:"approvals,omitempty"`
	Suggestions    []string                 `json:"suggestions,omitempty"`
	ToolsUsed      []string                 `json:"toolsUsed"`
}

const systemPrompt = `You are Dispatcher's AI workload planner.

Given a workload directory, you decide where it should run, what it will cost, and what could go wrong.

You have 4 tools:

1. inspect_workload — tells you what the workload is (language, ports, GPU needs, secrets, etc.)
2. evaluate_all_targets — evaluates every configured target at once: feasibility, cost, risks, and required approvals. Call this AFTER inspect_workload.
3. find_cheapest_instances — searches the cloud VM catalog for specific instance pricing. Use when comparing cloud options.
4. get_run_history — checks what happened in past runs on a target. Use to validate estimates.

Workflow: inspect first, then evaluate all targets, then optionally drill into instances or history.

Your output should be a clear recommendation:
- Which target and why (reference the cost, risk, and capability data you received)
- What alternatives exist and what you'd trade off
- What was rejected and why
- What risks the user should know about
- What approvals are needed
- Any suggestions (missing Dockerfile, budget too low, consider spot instances, etc.)

Be direct. Use the actual numbers from the tools. Don't hedge — make a recommendation.`

// Plan generates an intelligent plan using the LLM backend.
func (p *Planner) Plan(ctx context.Context, path string, constraints types.PlanConstraints) (*PlanResult, error) {
	userMsg := fmt.Sprintf("Plan execution for the workload at: %s", path)
	if constraints.MaxEstimatedCostUSD > 0 {
		userMsg += fmt.Sprintf("\nBudget: $%.2f maximum.", constraints.MaxEstimatedCostUSD)
	}
	if constraints.MaxDuration > 0 {
		userMsg += fmt.Sprintf("\nTime limit: %s.", constraints.MaxDuration)
	}
	if constraints.TargetName != "" {
		userMsg += fmt.Sprintf("\nPreferred target: %s.", constraints.TargetName)
	}
	if constraints.OptimizeFor == types.OptimizeSpeed {
		userMsg += "\nOptimize for speed over cost."
	}

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userMsg},
	}

	toolDefs := p.tools.Definitions()
	var toolsUsed []string
	var spec *types.WorkloadSpec

	for turn := 0; turn < p.maxTurns; turn++ {
		response, err := p.backend.Chat(ctx, messages, toolDefs)
		if err != nil {
			return nil, fmt.Errorf("LLM call failed: %w", err)
		}
		messages = append(messages, *response)

		if len(response.ToolCalls) == 0 {
			for _, name := range response.ToolsUsed {
				toolsUsed = append(toolsUsed, StripMCPPrefix(name))
			}
			res := &PlanResult{
				Explanation: response.Content,
				ToolsUsed:   toolsUsed,
			}
			mergeStructuredOutput(res, response.Content)
			return res, nil
		}

		for _, call := range response.ToolCalls {
			toolsUsed = append(toolsUsed, call.Name)
			result := p.tools.Execute(call, spec)

			if call.Name == "inspect_workload" && result.Error == "" {
				if s, ok := result.Result.(types.WorkloadSpec); ok {
					spec = &s
				}
			}

			messages = append(messages, Message{
				Role:       "tool_result",
				ToolResult: &result,
			})
		}
	}

	return nil, fmt.Errorf("planner exceeded maximum turns (%d)", p.maxTurns)
}

// DeterministicPlan runs the same tool pipeline without an LLM.
// Useful as a fallback or when no API key is configured.
func (p *Planner) DeterministicPlan(ctx context.Context, path string, constraints types.PlanConstraints) (*PlanResult, error) {
	// Step 1: Inspect
	inspectResult := p.tools.Execute(ToolCall{
		Name:  "inspect_workload",
		Input: mustJSON(map[string]string{"path": path}),
	}, nil)
	if inspectResult.Error != "" {
		return nil, fmt.Errorf("inspection failed: %s", inspectResult.Error)
	}
	spec, ok := inspectResult.Result.(types.WorkloadSpec)
	if !ok {
		return nil, fmt.Errorf("unexpected inspection result type")
	}

	// Step 2: Evaluate all targets at once
	evalResult := p.tools.Execute(ToolCall{
		Name:  "evaluate_all_targets",
		Input: json.RawMessage("{}"),
	}, &spec)

	evals, _ := evalResult.Result.([]TargetEvaluation)

	var result PlanResult
	result.ToolsUsed = []string{"inspect_workload", "evaluate_all_targets"}

	// Separate feasible from rejected
	type scored struct {
		eval TargetEvaluation
		cfg  types.TargetConfig
	}
	var feasible []scored

	for _, ev := range evals {
		if !ev.Feasible {
			reason := "not feasible"
			if len(ev.Reasons) > 0 {
				reason = ev.Reasons[0]
			}
			result.Rejected = append(result.Rejected, types.RejectedTarget{
				Target: ev.TargetID,
				Reason: reason,
			})
			continue
		}

		// Budget filter
		if constraints.MaxEstimatedCostUSD > 0 && ev.Cost != nil && ev.Cost.Value > constraints.MaxEstimatedCostUSD {
			result.Rejected = append(result.Rejected, types.RejectedTarget{
				Target: ev.TargetID,
				Reason: fmt.Sprintf("estimated cost $%.2f exceeds budget $%.2f", ev.Cost.Value, constraints.MaxEstimatedCostUSD),
			})
			continue
		}

		cfg, _ := p.tools.registry.Get(ev.TargetID)
		feasible = append(feasible, scored{eval: ev, cfg: cfg})
	}

	if len(feasible) == 0 {
		result.Explanation = "No feasible targets found for this workload."
		return &result, nil
	}

	// Sort by cost
	for i := 0; i < len(feasible); i++ {
		for j := i + 1; j < len(feasible); j++ {
			ci, cj := 0.0, 0.0
			if feasible[i].eval.Cost != nil {
				ci = feasible[i].eval.Cost.Value
			}
			if feasible[j].eval.Cost != nil {
				cj = feasible[j].eval.Cost.Value
			}
			if cj < ci {
				feasible[i], feasible[j] = feasible[j], feasible[i]
			}
		}
	}

	best := feasible[0]
	costVal := 0.0
	if best.eval.Cost != nil {
		costVal = best.eval.Cost.Value
		result.Recommendation = &types.Recommendation{
			Target:        best.eval.TargetID,
			Runtime:       target.RuntimeForTarget(best.cfg),
			EstimatedCost: *best.eval.Cost,
		}
	} else {
		result.Recommendation = &types.Recommendation{
			Target:  best.eval.TargetID,
			Runtime: target.RuntimeForTarget(best.cfg),
		}
	}
	result.Risks = best.eval.Risks
	result.Approvals = best.eval.Approvals

	for _, s := range feasible[1:] {
		alt := types.Alternative{
			Target:  s.eval.TargetID,
			Runtime: target.RuntimeForTarget(s.cfg),
		}
		if s.eval.Cost != nil {
			alt.EstimatedCost = *s.eval.Cost
		}
		result.Alternatives = append(result.Alternatives, alt)
	}

	result.Explanation = fmt.Sprintf(
		"Recommended: %s at $%.2f (%s confidence). %d alternative(s), %d rejected, %d risk(s).",
		best.eval.TargetID, costVal,
		best.eval.Cost.Confidence,
		len(result.Alternatives), len(result.Rejected), len(result.Risks),
	)

	return &result, nil
}

func mustJSON(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

// mergeStructuredOutput is invoked after the loop ends so agentic backends
// that return a single JSON message can populate typed PlanResult fields.
func mergeStructuredOutput(res *PlanResult, content string) {
	var parsed PlanResult
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return
	}
	if parsed.Explanation != "" {
		res.Explanation = parsed.Explanation
	}
	res.Recommendation = parsed.Recommendation
	res.Alternatives = parsed.Alternatives
	res.Rejected = parsed.Rejected
	res.Risks = parsed.Risks
	res.Approvals = parsed.Approvals
	res.Suggestions = parsed.Suggestions
	for _, name := range parsed.ToolsUsed {
		res.ToolsUsed = append(res.ToolsUsed, StripMCPPrefix(name))
	}
}
