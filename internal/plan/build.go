package plan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/policy"
	"github.com/d0cd/dispatcher/internal/risk"
	"github.com/d0cd/dispatcher/internal/target"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/d0cd/dispatcher/internal/workload"
)

type candidate struct {
	target types.TargetConfig
	cost   types.CostEstimate
}

// Build generates a complete plan for the workload at the given path.
func Build(path string, constraints types.PlanConstraints) (*types.Plan, error) {
	// Inspect workload (includes dispatch.yaml overrides)
	spec, err := workload.InspectCodebase(path)
	if err != nil {
		return nil, fmt.Errorf("workload inspection failed: %w", err)
	}

	// Merge dispatch.yaml constraints (file config) into plan constraints.
	// CLI flags take precedence — only fill in unset values.
	if cfg, _ := workload.LoadConfig(path); cfg != nil {
		if constraints.MaxEstimatedCostUSD == 0 && cfg.MaxCost > 0 {
			constraints.MaxEstimatedCostUSD = cfg.MaxCost
		}
		if constraints.MaxDuration == 0 && cfg.MaxTime != "" {
			if d, err := time.ParseDuration(cfg.MaxTime); err == nil {
				constraints.MaxDuration = d
			}
		}
		if constraints.TargetName == "" && cfg.Target != "" {
			constraints.TargetName = cfg.Target
		}
	}

	// Apply GPU override from constraints
	if constraints.RequireGPU != "" {
		applyGPUOverride(&spec, constraints.RequireGPU)
	}

	// Load targets (builtins + user config)
	registry := target.NewRegistry()
	registry.LoadBuiltins()
	// User-defined targets override builtins; errors are non-fatal
	_ = registry.LoadUserConfig()

	var feasible []candidate
	var rejected []types.RejectedTarget

	targets := registry.List()

	// If a specific target is requested, only evaluate that one (but still show others as context)
	if constraints.TargetName != "" {
		t, ok := registry.Get(constraints.TargetName)
		if !ok {
			return nil, fmt.Errorf("target %q not found", constraints.TargetName)
		}
		result := target.CheckFeasibility(t, spec)
		if !result.Feasible {
			return nil, fmt.Errorf("target %q is not feasible: %s", constraints.TargetName, result.Reasons[0])
		}
		est := cost.EstimateCost(spec, t)
		feasible = append(feasible, candidate{target: t, cost: est})

		// Evaluate rest as alternatives
		for _, other := range targets {
			if other.ID == constraints.TargetName {
				continue
			}
			result := target.CheckFeasibility(other, spec)
			if result.Feasible {
				est := cost.EstimateCost(spec, other)
				feasible = append(feasible, candidate{target: other, cost: est})
			} else {
				rejected = append(rejected, types.RejectedTarget{
					Target: other.ID,
					Reason: result.Reasons[0],
				})
			}
		}
	} else {
		for _, t := range targets {
			result := target.CheckFeasibility(t, spec)
			if result.Feasible {
				est := cost.EstimateCost(spec, t)
				feasible = append(feasible, candidate{target: t, cost: est})
			} else {
				rejected = append(rejected, types.RejectedTarget{
					Target: t.ID,
					Reason: result.Reasons[0],
				})
			}
		}
	}

	if len(feasible) == 0 {
		return nil, fmt.Errorf("no feasible targets found for workload")
	}

	// Sort feasible by cost or speed (skip if a specific target was requested)
	if constraints.TargetName == "" {
		sortCandidates(feasible, constraints.OptimizeFor)
	}

	// Filter by max cost
	if constraints.MaxEstimatedCostUSD > 0 {
		var filtered []candidate
		for _, c := range feasible {
			if c.cost.Value <= constraints.MaxEstimatedCostUSD {
				filtered = append(filtered, c)
			} else {
				rejected = append(rejected, types.RejectedTarget{
					Target: c.target.ID,
					Reason: fmt.Sprintf("estimated cost $%.2f exceeds budget $%.2f", c.cost.Value, constraints.MaxEstimatedCostUSD),
				})
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("no targets within budget of $%.2f", constraints.MaxEstimatedCostUSD)
		}
		feasible = filtered
	}

	// Build recommendation (first is best)
	best := feasible[0]
	rec := &types.Recommendation{
		Target:        best.target.ID,
		Runtime:       target.RuntimeForTarget(best.target),
		EstimatedCost: best.cost,
		Reason:        buildReasons(spec, best.target),
	}

	// Build alternatives
	var alternatives []types.Alternative
	for _, c := range feasible[1:] {
		alternatives = append(alternatives, types.Alternative{
			Target:        c.target.ID,
			Runtime:       target.RuntimeForTarget(c.target),
			EstimatedCost: c.cost,
			Tradeoff:      buildTradeoffs(c.target, best.target),
		})
	}

	// Risk analysis
	risks := risk.Analyze(spec, best.target, best.cost)

	// Policy evaluation
	approvals := policy.Evaluate(spec, best.target, best.cost)

	// Validation
	validation := validate(spec, best.target, best.cost)

	// Execution steps
	steps := buildExecutionSteps(spec, best.target)

	p := &types.Plan{
		APIVersion: "dispatcher.dev/v1",
		Kind:       "Plan",
		Metadata: types.PlanMetadata{
			ID:        generatePlanID(),
			CreatedAt: time.Now().UTC(),
			CreatedBy: "dispatcher-cli",
		},
		Workload:          spec,
		Constraints:       constraints,
		Recommendation:    rec,
		Alternatives:      alternatives,
		Rejected:          rejected,
		Risks:             risks,
		Validation:        validation,
		RequiredApprovals: approvals,
		ExecutionSteps:    steps,
	}

	return p, nil
}

func sortCandidates(candidates []candidate, optimize types.OptimizeGoal) {
	sort.Slice(candidates, func(i, j int) bool {
		if optimize == types.OptimizeSpeed {
			// Prefer local targets for speed
			iLocal := candidates[i].target.Kind == types.TargetKindLocal || candidates[i].target.Kind == types.TargetKindDocker || candidates[i].target.Kind == types.TargetKindLocalVM
			jLocal := candidates[j].target.Kind == types.TargetKindLocal || candidates[j].target.Kind == types.TargetKindDocker || candidates[j].target.Kind == types.TargetKindLocalVM
			if iLocal != jLocal {
				return iLocal
			}
		}
		return candidates[i].cost.Value < candidates[j].cost.Value
	})
}

func buildReasons(w types.WorkloadSpec, t types.TargetConfig) []string {
	var reasons []string

	if w.Package.Dockerfile != "" {
		reasons = append(reasons, "workload is containerized")
	}
	if len(w.Ports) > 0 {
		reasons = append(reasons, fmt.Sprintf("service port %d detected", w.Ports[0]))
	}
	if !w.Requirements.GPU.Required {
		reasons = append(reasons, "no GPU required")
	} else {
		reasons = append(reasons, fmt.Sprintf("GPU required (%s)", w.Requirements.GPU.Framework))
	}
	if t.Kind == types.TargetKindDocker || t.Kind == types.TargetKindLocal || t.Kind == types.TargetKindLocalVM {
		reasons = append(reasons, "local execution has zero marginal cost")
	}
	if t.Kind == types.TargetKindLocal {
		reasons = append(reasons, "runs as local process, no container overhead")
	}
	if t.Kind == types.TargetKindLocalVM {
		reasons = append(reasons, "runs in isolated local VM")
	}
	if t.Capabilities.Networking.PrivateVPCAccess {
		reasons = append(reasons, "target has private network access")
	}

	return reasons
}

func buildTradeoffs(alt, best types.TargetConfig) []string {
	var tradeoffs []string

	if alt.Kind == types.TargetKindModal {
		tradeoffs = append(tradeoffs, "simpler autoscaling")
		tradeoffs = append(tradeoffs, "less private networking control")
	}
	if alt.Kind == types.TargetKindCloudVM {
		tradeoffs = append(tradeoffs, "more isolation")
		tradeoffs = append(tradeoffs, "more setup and cleanup overhead")
	}
	if alt.Kind == types.TargetKindE2B {
		tradeoffs = append(tradeoffs, "sandboxed execution")
		tradeoffs = append(tradeoffs, "limited to short-lived tasks")
	}
	if alt.Kind == types.TargetKindDocker && best.Kind != types.TargetKindDocker {
		tradeoffs = append(tradeoffs, "zero marginal cost")
		tradeoffs = append(tradeoffs, "limited to local resources")
	}
	if alt.Kind == types.TargetKindKubernetes {
		tradeoffs = append(tradeoffs, "production-grade orchestration")
		tradeoffs = append(tradeoffs, "requires cluster access")
	}

	if len(tradeoffs) == 0 {
		tradeoffs = append(tradeoffs, "different operational characteristics")
	}

	return tradeoffs
}

func validate(w types.WorkloadSpec, t types.TargetConfig, est types.CostEstimate) types.ValidationResult {
	v := types.ValidationResult{
		Schema:             types.ValidationPass,
		PackageBuild:       types.ValidationPass,
		TargetCapabilities: types.ValidationPass,
		Credentials:        types.ValidationSkipped,
		Quota:              types.ValidationSkipped,
		Network:            types.ValidationPass,
		Policy:             types.ValidationPass,
		CostEstimate:       types.ValidationPass,
		CleanupPlan:        types.ValidationPass,
	}

	if w.Package.BuildRequired && w.Package.Dockerfile == "" && w.Package.BaseImage == "" {
		v.PackageBuild = types.ValidationWarn
	}

	if est.Confidence == types.ConfidenceUnknown {
		v.CostEstimate = types.ValidationFail
	}

	if len(w.Secrets) > 0 {
		v.Credentials = types.ValidationWarn
	}

	return v
}

func buildExecutionSteps(w types.WorkloadSpec, t types.TargetConfig) []string {
	var steps []string

	if w.Package.BuildRequired {
		steps = append(steps, "build-image")
		if t.Kind != types.TargetKindDocker {
			steps = append(steps, "push-image")
		}
	}

	switch w.DetectedKind {
	case types.WorkloadKindService:
		steps = append(steps, "deploy-service", "wait-for-health-check")
	default:
		steps = append(steps, "run-workload")
	}

	steps = append(steps, "stream-logs", "track-cost", "register-cleanup")

	return steps
}

func generatePlanID() string {
	return "plan_" + types.ShortID()
}

// applyGPUOverride parses a GPU spec like "1", "h100:1", or "a100:2" and
// overrides the workload's GPU requirements.
func applyGPUOverride(spec *types.WorkloadSpec, gpu string) {
	count := 1
	model := ""

	parts := strings.SplitN(gpu, ":", 2)
	if len(parts) == 2 {
		model = parts[0]
		if n, err := strconv.Atoi(parts[1]); err == nil && n > 0 {
			count = n
		}
	} else {
		if n, err := strconv.Atoi(gpu); err == nil && n > 0 {
			count = n
		}
	}

	spec.Requirements.GPU = types.GPURequirement{
		Required: true,
		Count:    count,
		Model:    model,
	}
	if spec.DetectedKind != types.WorkloadKindGPUJob {
		spec.DetectedKind = types.WorkloadKindGPUJob
	}
}
