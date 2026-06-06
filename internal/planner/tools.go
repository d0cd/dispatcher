package planner

import (
	"encoding/json"
	"fmt"

	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/policy"
	"github.com/d0cd/dispatcher/internal/risk"
	"github.com/d0cd/dispatcher/internal/target"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/d0cd/dispatcher/internal/workload"
)

// Tool represents a callable tool the AI planner can invoke.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Parameters  *ToolSchema `json:"parameters"`
}

// ToolSchema describes a tool's parameter structure.
type ToolSchema struct {
	Type       string                `json:"type"`
	Properties map[string]ToolParam  `json:"properties,omitempty"`
	Required   []string              `json:"required,omitempty"`
}

// ToolParam describes a single parameter.
type ToolParam struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// ToolCall is a request from the LLM to invoke a tool.
type ToolCall struct {
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// ToolResult is the response from executing a tool.
type ToolResult struct {
	Name   string `json:"name"`
	Result any    `json:"result"`
	Error  string `json:"error,omitempty"`
}

// TargetEvaluation is the combined result of evaluating a single target.
type TargetEvaluation struct {
	TargetID    string                    `json:"targetId"`
	Feasible    bool                      `json:"feasible"`
	Reasons     []string                  `json:"reasons,omitempty"`
	Cost        *types.CostEstimate       `json:"cost,omitempty"`
	Risks       []types.Risk              `json:"risks,omitempty"`
	Approvals   []types.PolicyRequirement `json:"approvals,omitempty"`
}

// ToolRegistry holds the tools available to the planner and executes them.
type ToolRegistry struct {
	registry *target.Registry
	history  *cost.HistoryStore
	catalog  *cloudvm.Catalog
}

// NewToolRegistry creates a registry with all planner tools wired up.
func NewToolRegistry(reg *target.Registry, hist *cost.HistoryStore, cat *cloudvm.Catalog) *ToolRegistry {
	return &ToolRegistry{
		registry: reg,
		history:  hist,
		catalog:  cat,
	}
}

// Definitions returns the tool schemas for the LLM.
func (tr *ToolRegistry) Definitions() []Tool {
	return []Tool{
		{
			Name:        "inspect_workload",
			Description: "Scan a directory to detect what kind of workload it is. Returns: runtime (python/node/go/etc), detected kind (script/service/gpu-job/etc), entrypoints, ports, GPU requirements, secrets referenced, data dependencies, and how it should be packaged.",
			Parameters: &ToolSchema{
				Type: "object",
				Properties: map[string]ToolParam{
					"path": {Type: "string", Description: "Path to the workload directory"},
				},
				Required: []string{"path"},
			},
		},
		{
			Name:        "evaluate_all_targets",
			Description: "Evaluate every configured target against the inspected workload. For each target, checks feasibility, estimates cost (using historical data when available), analyzes risks, and determines required approvals. Returns a complete evaluation for every target in one call.",
			Parameters: &ToolSchema{
				Type:       "object",
				Properties: map[string]ToolParam{},
			},
		},
		{
			Name:        "find_cheapest_instances",
			Description: "Search the cloud VM instance catalog for the cheapest instances matching the workload's compute requirements. Searches across AWS, GCP, Azure, and Hetzner. Returns up to 10 options sorted by price.",
			Parameters: &ToolSchema{
				Type: "object",
				Properties: map[string]ToolParam{
					"min_vcpus":     {Type: "integer", Description: "Minimum vCPU count needed"},
					"min_memory_gb": {Type: "number", Description: "Minimum memory in GB"},
					"gpu_count":     {Type: "integer", Description: "Number of GPUs needed (0 if none)"},
					"gpu_model":     {Type: "string", Description: "Specific GPU model (t4, a100, h100, l4) or empty for any"},
					"arch":          {Type: "string", Description: "CPU architecture (x86_64, arm64) or empty for any"},
				},
			},
		},
		{
			Name:        "get_run_history",
			Description: "Get historical statistics from past runs on a specific target. Returns: total runs, success count, average cost, and average duration. Use this to validate or improve cost/duration estimates.",
			Parameters: &ToolSchema{
				Type: "object",
				Properties: map[string]ToolParam{
					"target_id": {Type: "string", Description: "Target ID to get history for"},
				},
				Required: []string{"target_id"},
			},
		},
	}
}

// Execute runs a tool call and returns the result.
func (tr *ToolRegistry) Execute(call ToolCall, spec *types.WorkloadSpec) ToolResult {
	switch call.Name {
	case "inspect_workload":
		return tr.execInspect(call.Input)
	case "evaluate_all_targets":
		return tr.execEvaluateAll(spec)
	case "find_cheapest_instances":
		return tr.execFindInstances(call.Input)
	case "get_run_history":
		return tr.execGetHistory(call.Input)
	default:
		return ToolResult{Name: call.Name, Error: fmt.Sprintf("unknown tool: %s", call.Name)}
	}
}

func (tr *ToolRegistry) execInspect(input json.RawMessage) ToolResult {
	var params struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return ToolResult{Name: "inspect_workload", Error: err.Error()}
	}
	spec, err := workload.InspectCodebase(params.Path)
	if err != nil {
		return ToolResult{Name: "inspect_workload", Error: err.Error()}
	}
	return ToolResult{Name: "inspect_workload", Result: spec}
}

// execEvaluateAll runs feasibility, cost, risk, and policy for every target in one call.
func (tr *ToolRegistry) execEvaluateAll(spec *types.WorkloadSpec) ToolResult {
	if spec == nil {
		return ToolResult{Name: "evaluate_all_targets", Error: "no workload inspected yet — call inspect_workload first"}
	}

	targets := tr.registry.List()
	var evals []TargetEvaluation

	for _, t := range targets {
		eval := TargetEvaluation{TargetID: t.ID}

		fr := target.CheckFeasibility(t, *spec)
		eval.Feasible = fr.Feasible
		eval.Reasons = fr.Reasons

		if fr.Feasible {
			est := cost.EstimateCostWithHistory(*spec, t, tr.history)
			eval.Cost = &est
			eval.Risks = risk.Analyze(*spec, t, est)
			eval.Approvals = policy.Evaluate(*spec, t, est)
		}

		evals = append(evals, eval)
	}

	return ToolResult{Name: "evaluate_all_targets", Result: evals}
}

func (tr *ToolRegistry) execFindInstances(input json.RawMessage) ToolResult {
	var params struct {
		MinVCPUs    int     `json:"min_vcpus"`
		MinMemoryGB float64 `json:"min_memory_gb"`
		GPUCount    int     `json:"gpu_count"`
		GPUModel    string  `json:"gpu_model"`
		Arch        string  `json:"arch"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return ToolResult{Name: "find_cheapest_instances", Error: err.Error()}
	}
	if tr.catalog == nil {
		return ToolResult{Name: "find_cheapest_instances", Error: "no instance catalog available"}
	}
	results := tr.catalog.FindCheapest(cloudvm.InstanceRequirements{
		MinVCPUs:    params.MinVCPUs,
		MinMemoryGB: params.MinMemoryGB,
		GPUCount:    params.GPUCount,
		GPUModel:    params.GPUModel,
		Arch:        params.Arch,
	})
	if len(results) > 10 {
		results = results[:10]
	}
	return ToolResult{Name: "find_cheapest_instances", Result: results}
}

func (tr *ToolRegistry) execGetHistory(input json.RawMessage) ToolResult {
	var params struct {
		TargetID string `json:"target_id"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return ToolResult{Name: "get_run_history", Error: err.Error()}
	}
	if tr.history == nil {
		return ToolResult{Name: "get_run_history", Result: "no history available"}
	}
	stats := tr.history.Stats(params.TargetID)
	return ToolResult{Name: "get_run_history", Result: stats}
}
