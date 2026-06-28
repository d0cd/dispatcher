package planner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/policy"
	"github.com/d0cd/dispatcher/internal/risk"
	"github.com/d0cd/dispatcher/internal/run"
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
	Type       string               `json:"type"`
	Properties map[string]ToolParam `json:"properties,omitempty"`
	Required   []string             `json:"required,omitempty"`
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
	TargetID  string                    `json:"targetId"`
	Feasible  bool                      `json:"feasible"`
	Reasons   []string                  `json:"reasons,omitempty"`
	Cost      *types.CostEstimate       `json:"cost,omitempty"`
	Risks     []types.Risk              `json:"risks,omitempty"`
	Approvals []types.PolicyRequirement `json:"approvals,omitempty"`
}

// ToolRegistry holds the tools available to the planner and executes them.
//
// workloadRoot is the security boundary for path-taking tools: inspect_workload
// can only read inside this directory. The LLM-supplied `path` arg is
// resolved and verified to be within workloadRoot, OR the LLM is allowed to
// omit the path and we default to workloadRoot itself. Anything outside the
// root is rejected — without this, the LLM could pass `/etc/passwd`.
type ToolRegistry struct {
	registry *target.Registry
	history  *cost.HistoryStore
	catalog  *cloudvm.Catalog

	// rootMu guards workloadRoot. Concurrent Plan/Audit/Diagnose calls on
	// a shared registry would otherwise race: one caller's SetWorkloadRoot
	// could be observed by the other's Execute, applying the wrong
	// containment boundary.
	rootMu       sync.RWMutex
	workloadRoot string // absolute, resolved, no trailing slash
}

// NewToolRegistry creates a registry with all planner tools wired up. The
// workload root is set later via SetWorkloadRoot; tools that need a path
// boundary error if SetWorkloadRoot wasn't called.
func NewToolRegistry(reg *target.Registry, hist *cost.HistoryStore, cat *cloudvm.Catalog) *ToolRegistry {
	return &ToolRegistry{
		registry: reg,
		history:  hist,
		catalog:  cat,
	}
}

// SetWorkloadRoot establishes the directory that path-taking tools are
// allowed to read. Called once per planner invocation, before any tools
// run. Resolves to an absolute path so symlink tricks can't escape.
func (tr *ToolRegistry) SetWorkloadRoot(path string) error {
	if path == "" {
		tr.rootMu.Lock()
		tr.workloadRoot = ""
		tr.rootMu.Unlock()
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve workload root: %w", err)
	}
	// EvalSymlinks ensures we compare against the real path. If the root
	// is a symlink to /etc, this canonicalizes so a subsequent path
	// containment check catches it.
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		abs = resolved
	}
	tr.rootMu.Lock()
	tr.workloadRoot = filepath.Clean(abs)
	tr.rootMu.Unlock()
	return nil
}

// WorkloadRoot returns the configured root (empty string when unset).
// Exposed for callers (e.g. tests) that want to verify scoping.
func (tr *ToolRegistry) WorkloadRoot() string {
	tr.rootMu.RLock()
	defer tr.rootMu.RUnlock()
	return tr.workloadRoot
}

// resolveWorkloadPath verifies that `requested` (which may be empty,
// relative, or absolute) resolves to a location at or under workloadRoot.
// Returns the cleaned absolute path. An empty requested defaults to the
// root itself.
func (tr *ToolRegistry) resolveWorkloadPath(requested string) (string, error) {
	tr.rootMu.RLock()
	root := tr.workloadRoot
	tr.rootMu.RUnlock()

	if root == "" {
		return "", fmt.Errorf("workload root not configured (planner did not call SetWorkloadRoot before invoking the tool)")
	}
	target := requested
	if target == "" {
		return root, nil
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(root, target)
	}
	target = filepath.Clean(target)
	// Resolve symlinks if the target exists — otherwise we'd let a
	// workload-planted symlink escape the root via path-cleanup alone.
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}
	rootWithSep := root + string(filepath.Separator)
	if target != root && !strings.HasPrefix(target, rootWithSep) {
		return "", fmt.Errorf("path %q is outside the workload root %q", requested, root)
	}
	return target, nil
}

// Definitions returns the tool schemas for the LLM.
func (tr *ToolRegistry) Definitions() []Tool {
	return []Tool{
		{
			Name:        "inspect_workload",
			Description: "Scan the workload directory to detect what kind of workload it is. Returns: runtime (python/node/go/etc), detected kind (script/service/gpu-job/etc), entrypoints, ports, GPU requirements, secrets referenced, data dependencies, and how it should be packaged. The path argument MUST be inside the workload directory dispatcher was invoked against — paths outside that root are rejected. If you don't pass a path, the workload root is used.",
			Parameters: &ToolSchema{
				Type: "object",
				Properties: map[string]ToolParam{
					"path": {Type: "string", Description: "Path inside the workload directory (defaults to the root if omitted). Paths outside the workload root are rejected."},
				},
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
		{
			Name:        "inspect_run",
			Description: "Load a persisted run by ID and return its current state, error message (if any), realized cost, lifecycle, and the tail of its log file. Use this as the starting point when diagnosing a failed, stuck, or surprising run.",
			Parameters: &ToolSchema{
				Type: "object",
				Properties: map[string]ToolParam{
					"run_id":    {Type: "string", Description: "Run ID to inspect (e.g. run_abc123)"},
					"log_lines": {Type: "integer", Description: "Number of trailing log lines to include (default 50, max 500)"},
				},
				Required: []string{"run_id"},
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
	case "inspect_run":
		return tr.execInspectRun(call.Input)
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
	// Containment check: the LLM-supplied path is allowed only inside the
	// configured workload root. Without this, an LLM (or an attacker who
	// got prompt-injection-style influence over it) could ask us to
	// inspect /etc, /root, etc., and we'd happily read the operator's
	// filesystem and return contents in the tool result.
	resolved, err := tr.resolveWorkloadPath(params.Path)
	if err != nil {
		return ToolResult{Name: "inspect_workload", Error: err.Error()}
	}
	spec, err := workload.InspectCodebase(resolved)
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
			est := cost.EstimateCostWithHistory(*spec, t, tr.history, tr.catalog)
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

// RunInspection is the structured payload returned to the LLM by inspect_run.
type RunInspection struct {
	ID            string             `json:"id"`
	State         types.RunState     `json:"state"`
	TargetID      string             `json:"targetId"`
	Owner         string             `json:"owner,omitempty"`
	StartedAt     string             `json:"startedAt,omitempty"`
	FinishedAt    string             `json:"finishedAt,omitempty"`
	DurationSec   float64            `json:"durationSec,omitempty"`
	Error         string             `json:"error,omitempty"`
	Cost          types.CostEstimate `json:"cost"`
	Lifecycle     string             `json:"lifecycle,omitempty"`
	LastHeartbeat string             `json:"lastHeartbeat,omitempty"`
	LogFile       string             `json:"logFile,omitempty"`
	LogTail       []string           `json:"logTail,omitempty"`
	LogTruncated  bool               `json:"logTruncated,omitempty"`
	// Failure surfaces the adapter-reported exit code / signal / OOM flag
	// so the diagnostician (LLM or deterministic) can distinguish workload
	// bugs from environmental failures (OOM, preemption).
	ExitCode     int    `json:"exitCode,omitempty"`
	Signal       string `json:"signal,omitempty"`
	OOMKilled    bool   `json:"oomKilled,omitempty"`
	FailureClass string `json:"failureClass,omitempty"` // permanent | transient | unknown
	RetryCount   int    `json:"retryCount,omitempty"`
	// Attestation surfaces a confidential run's TEE verdict (R13) so the
	// diagnostician sees whether the run was actually proven. Nil for
	// non-confidential runs.
	Attestation *cloudvm.AttestationResult `json:"attestation,omitempty"`
}

const (
	defaultInspectRunLogLines = 50
	maxInspectRunLogLines     = 500
)

func (tr *ToolRegistry) execInspectRun(input json.RawMessage) ToolResult {
	var params struct {
		RunID    string `json:"run_id"`
		LogLines int    `json:"log_lines"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return ToolResult{Name: "inspect_run", Error: err.Error()}
	}
	if params.RunID == "" {
		return ToolResult{Name: "inspect_run", Error: "run_id is required"}
	}

	rec, err := run.LoadRecord(params.RunID)
	if err != nil {
		return ToolResult{Name: "inspect_run", Error: err.Error()}
	}

	lines := params.LogLines
	if lines <= 0 {
		lines = defaultInspectRunLogLines
	}
	if lines > maxInspectRunLogLines {
		lines = maxInspectRunLogLines
	}
	tail, truncated := readLogTail(rec.LogFile, lines)

	insp := RunInspection{
		ID:           rec.ID,
		State:        rec.State,
		TargetID:     rec.TargetID,
		Owner:        rec.Owner,
		Error:        rec.Error,
		Cost:         rec.Cost,
		Lifecycle:    string(rec.Lifecycle),
		LogFile:      rec.LogFile,
		LogTail:      tail,
		LogTruncated: truncated,
		ExitCode:     rec.Failure.ExitCode,
		Signal:       rec.Failure.Signal,
		OOMKilled:    rec.Failure.OOMKilled,
		RetryCount:   rec.RetryCount,
		Attestation:  cloudvm.AttestationFromHandleState(rec.HandleState),
	}
	if rec.State == types.RunStateExecutionFailed {
		// Only classify when there's actually a failure to classify.
		// Re-import-cycle-safe: classify lives in adapter package which
		// planner already imports for ToolRegistry.
		insp.FailureClass = string(adapter.ClassifyFailure(rec.Failure))
	}
	if !rec.StartedAt.IsZero() {
		insp.StartedAt = rec.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if !rec.FinishedAt.IsZero() {
		insp.FinishedAt = rec.FinishedAt.UTC().Format("2006-01-02T15:04:05Z")
		if !rec.StartedAt.IsZero() {
			insp.DurationSec = rec.FinishedAt.Sub(rec.StartedAt).Seconds()
		}
	}
	if !rec.LastHeartbeat.IsZero() {
		insp.LastHeartbeat = rec.LastHeartbeat.UTC().Format("2006-01-02T15:04:05Z")
	}

	return ToolResult{Name: "inspect_run", Result: insp}
}

// readLogTail returns up to n trailing lines from a log file. truncated is
// true when the file had more lines than were returned. A missing or unreadable
// file returns (nil, false) — the run record itself is still useful.
//
// Bounded read: we tail at most maxLogTailBytes from the END of the file
// without loading the whole thing into memory. A workload writing a
// multi-GB log would otherwise OOM the planner the moment the LLM asks for
// log_tail. The byte cap is then sliced into lines and clipped to n trailing
// lines.
func readLogTail(path string, n int) (lines []string, truncated bool) {
	if path == "" {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, false
	}
	size := info.Size()
	tail := int64(maxLogTailBytes)
	startedTruncated := false
	if size > tail {
		if _, err := f.Seek(size-tail, io.SeekStart); err != nil {
			return nil, false
		}
		startedTruncated = true
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, false
	}
	// If we seeked into the middle of a line, drop the first (partial) one
	// so callers don't see truncated nonsense.
	if startedTruncated {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(all) <= n {
		return all, startedTruncated
	}
	return all[len(all)-n:], true
}

// maxLogTailBytes bounds the byte window readLogTail will load when
// returning a tail to the diagnostician. Sized generously enough for
// thousands of typical log lines but small enough that a runaway workload
// can't OOM the planner.
const maxLogTailBytes = 1 << 20 // 1 MiB
