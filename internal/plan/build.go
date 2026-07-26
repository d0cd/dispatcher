package plan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/dlog"
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

// estimateCost prices a target, applying the spot discount when the run requested
// an interruptible instance (a spot-incapable provider is unaffected).
func estimateCost(spec types.WorkloadSpec, t types.TargetConfig, catalog *cloudvm.Catalog, spot bool) types.CostEstimate {
	est := cost.EstimateCost(spec, t, catalog)
	if spot {
		est = cost.ApplySpot(est, t)
	}
	return est
}

// Build generates a complete plan for the workload at the given path.
//
// catalog supplies live cloud pricing; pass nil when no catalog is available
// (offline, tests). Cloud-vm targets without catalog data are surfaced with
// ConfidenceUnknown rather than a misleading static estimate.
func Build(path string, constraints types.PlanConstraints, catalog *cloudvm.Catalog) (*types.Plan, error) {
	// Inspect workload (includes dispatcher.yaml overrides)
	spec, err := workload.InspectCodebase(path)
	if err != nil {
		return nil, fmt.Errorf("workload inspection failed: %w", err)
	}

	// Merge dispatcher.yaml constraints (file config) into plan constraints.
	// CLI flags take precedence — only fill in unset values. A malformed config
	// is a hard error (InspectCodebase above already aborts on it; this guards
	// the direct call path too) rather than a silent drop of the constraints.
	cfg, cfgErr := workload.LoadConfig(path)
	if cfgErr != nil {
		return nil, fmt.Errorf("load dispatcher config: %w", cfgErr)
	}
	if cfg != nil {
		// Secret-resolution commands are honored only from the user-global config
		// (~/.config/dispatcher/config.yaml, registered at CLI startup). A per-project
		// dispatcher.yaml must NOT be able to define a command that runs against the
		// operator's unlocked secret manager, so a project secrets: block is ignored
		// with a warning rather than silently.
		if len(cfg.Secrets) > 0 {
			dlog.L().Warn("secrets.per_project_ignored",
				"note", "per-project secrets: are not executed; put operator credentials in ~/.config/dispatcher/config.yaml",
				"count", len(cfg.Secrets))
		}
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
		if constraints.Region == "" && cfg.Region != "" {
			constraints.Region = cfg.Region
		}
		if constraints.WatchdogTTL == 0 && cfg.WatchdogTTL != "" {
			if d, err := time.ParseDuration(cfg.WatchdogTTL); err == nil {
				constraints.WatchdogTTL = d
			}
		}
		if !constraints.RetryTransientFailures && cfg.RetryTransientFailures != nil {
			constraints.RetryTransientFailures = *cfg.RetryTransientFailures
		}
		if !constraints.Spot && cfg.Spot {
			constraints.Spot = true
		}
	}

	// Apply GPU override from constraints
	if constraints.RequireGPU != "" {
		if err := applyGPUOverride(&spec, constraints.RequireGPU); err != nil {
			return nil, err
		}
	}

	// Load targets (builtins + user config)
	registry := target.NewRegistry()
	registry.LoadBuiltins()
	// User-defined targets override builtins; errors are non-fatal but
	// recorded so misconfigured user targets aren't invisible.
	if err := registry.LoadUserConfig(); err != nil {
		dlog.L().Warn("plan.user_targets_load_failed", "err", err.Error())
	}

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
		est := estimateCost(spec, t, catalog, constraints.Spot)
		feasible = append(feasible, candidate{target: t, cost: est})

		// Evaluate rest as alternatives
		for _, other := range targets {
			if other.ID == constraints.TargetName {
				continue
			}
			result := target.CheckFeasibility(other, spec)
			if result.Feasible {
				est := estimateCost(spec, other, catalog, constraints.Spot)
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
				est := estimateCost(spec, t, catalog, constraints.Spot)
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

	// Order the candidates and apply the budget filter.
	feasible, budgetRejected, err := orderAndFilter(feasible, constraints)
	if err != nil {
		return nil, err
	}
	rejected = append(rejected, budgetRejected...)

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
	risks := risk.Analyze(spec, best.target, best.cost, constraints.Spot)

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

// orderAndFilter sorts feasible candidates (unless a target was pinned, in
// which case the caller has already placed it at index 0) and applies the
// budget filter. It returns the surviving candidates and the targets rejected
// for cost. A pinned target that busts the budget is a conflict the user must
// see, so it returns an error rather than silently rerouting to a cheaper
// alternative; unknown-cost estimates cannot be confirmed within a budget and
// are rejected when one is set.
func orderAndFilter(feasible []candidate, constraints types.PlanConstraints) ([]candidate, []types.RejectedTarget, error) {
	if constraints.TargetName == "" {
		sortCandidates(feasible, constraints.OptimizeFor)
	}

	budget := constraints.MaxEstimatedCostUSD
	if budget <= 0 {
		return feasible, nil, nil
	}

	var kept []candidate
	var rejected []types.RejectedTarget
	for _, c := range feasible {
		unknown := c.cost.Confidence == types.ConfidenceUnknown
		if !unknown && c.cost.Value <= budget {
			kept = append(kept, c)
			continue
		}
		if constraints.TargetName == c.target.ID {
			if unknown {
				return nil, nil, fmt.Errorf("requested target %q has unknown cost and cannot be confirmed within budget $%.2f", c.target.ID, budget)
			}
			return nil, nil, fmt.Errorf("requested target %q estimated $%.2f exceeds budget $%.2f", c.target.ID, c.cost.Value, budget)
		}
		reason := fmt.Sprintf("estimated cost $%.2f exceeds budget $%.2f", c.cost.Value, budget)
		if unknown {
			reason = fmt.Sprintf("cost unknown; cannot confirm within budget $%.2f", budget)
		}
		rejected = append(rejected, types.RejectedTarget{Target: c.target.ID, Reason: reason})
	}
	if len(kept) == 0 {
		return nil, nil, fmt.Errorf("no targets within budget of $%.2f", budget)
	}
	return kept, rejected, nil
}

func sortCandidates(candidates []candidate, optimize types.OptimizeGoal) {
	sort.Slice(candidates, func(i, j int) bool {
		// Unknown-cost candidates are non-orderable by price; sort them after
		// every priced candidate so a $0 "unknown" can't masquerade as cheapest.
		iUnknown := candidates[i].cost.Confidence == types.ConfidenceUnknown
		jUnknown := candidates[j].cost.Confidence == types.ConfidenceUnknown
		if iUnknown != jUnknown {
			return jUnknown
		}
		if optimize == types.OptimizeSpeed {
			// Prefer local targets for speed
			iLocal := candidates[i].target.Kind == types.TargetKindLocal || candidates[i].target.Kind == types.TargetKindDocker || candidates[i].target.Kind == types.TargetKindLocalVM
			jLocal := candidates[j].target.Kind == types.TargetKindLocal || candidates[j].target.Kind == types.TargetKindDocker || candidates[j].target.Kind == types.TargetKindLocalVM
			if iLocal != jLocal {
				return iLocal
			}
			if !iLocal && !jLocal {
				// Among remote candidates, higher price is a rough proxy for more
				// compute (faster) — speed must NOT fall through to cheapest, which
				// picks the slowest VM. (A duration signal from history would be a
				// better proxy; see docs/ROADMAP.md.)
				return candidates[i].cost.Value > candidates[j].cost.Value
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

	if alt.Kind == types.TargetKindCloudVM {
		tradeoffs = append(tradeoffs, "more isolation")
		tradeoffs = append(tradeoffs, "more setup and cleanup overhead")
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
func applyGPUOverride(spec *types.WorkloadSpec, gpu string) error {
	count := 1
	model := ""

	parts := strings.SplitN(gpu, ":", 2)
	if len(parts) == 2 {
		model = parts[0]
		n, err := strconv.Atoi(parts[1])
		if err != nil || n <= 0 {
			return fmt.Errorf("invalid --gpu value %q: count must be a positive integer", gpu)
		}
		count = n
	} else {
		n, err := strconv.Atoi(gpu)
		if err != nil || n <= 0 {
			return fmt.Errorf("invalid --gpu value %q: count must be a positive integer", gpu)
		}
		count = n
	}

	spec.Requirements.GPU = types.GPURequirement{
		Required: true,
		Count:    count,
		Model:    model,
	}
	if spec.DetectedKind != types.WorkloadKindGPUJob {
		spec.DetectedKind = types.WorkloadKindGPUJob
	}
	return nil
}
