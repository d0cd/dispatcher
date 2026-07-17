package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/plan"
	"github.com/d0cd/dispatcher/internal/planner"
	"github.com/d0cd/dispatcher/internal/target"
	"github.com/d0cd/dispatcher/internal/types"
)

var planFlags struct {
	target   string
	optimize string
	maxCost  float64
	gpu      string
	ai       bool
}

var planCmd = &cobra.Command{
	Use:         "plan [path]",
	Annotations: map[string]string{supportsJSON: "true"},
	Short:       "Generate an execution plan for a workload (defaults to current directory)",
	Long:        "Inspects the workload at the given path, evaluates configured targets, and produces a structured plan with cost estimates, risks, and recommendations.\n\nIf path is omitted, the current directory is used.",
	Args:        cobra.MaximumNArgs(1),
	RunE:        runPlan,
}

func init() {
	planCmd.Flags().StringVar(&planFlags.target, "target", "", "evaluate a specific target")
	planCmd.Flags().StringVar(&planFlags.optimize, "optimize", "cost", "optimize for: cost, speed")
	planCmd.Flags().Float64Var(&planFlags.maxCost, "max-cost", 0, "maximum estimated cost in USD")
	planCmd.Flags().StringVar(&planFlags.gpu, "gpu", "", "GPU requirement (e.g. 1, a100:1)")
	planCmd.Flags().BoolVar(&planFlags.ai, "ai", false, "use AI planner (requires LLM backend)")
}

func runPlan(cmd *cobra.Command, args []string) error {
	if planFlags.maxCost < 0 {
		return fmt.Errorf("--max-cost must be >= 0 (0 means no cap); got %v", planFlags.maxCost)
	}
	raw := "."
	if len(args) > 0 {
		raw = args[0]
	}
	path, err := filepath.Abs(raw)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", raw, err)
	}

	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("path %s is not a valid directory", path)
	}

	optimizeFor, err := parseOptimize(planFlags.optimize)
	if err != nil {
		return err
	}

	constraints := types.PlanConstraints{
		TargetScope:         "workspace-defaults",
		OptimizeFor:         optimizeFor,
		MaxEstimatedCostUSD: planFlags.maxCost,
		RequireGPU:          planFlags.gpu,
		TargetName:          planFlags.target,
	}

	// Use the planner pipeline (deterministic by default, AI with --ai flag)
	if planFlags.ai {
		return runAIPlan(path, constraints)
	}

	catalog := loadLiveCatalog(os.Stderr)

	result, err := plan.Build(path, constraints, catalog)
	if err != nil {
		return fmt.Errorf("plan failed: %w", err)
	}

	if jsonOutput() {
		if _, err := plan.Save(result); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not save plan: %v\n", err)
		}
		return emitJSON(result)
	}

	plan.Print(result, color.Output)
	if footnote := formatPricingFootnote(catalog); footnote != "" {
		color.New(color.Faint).Fprintln(os.Stderr, footnote)
	}

	savedPath, err := plan.Save(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save plan: %v\n", err)
	} else {
		dim := color.New(color.Faint)
		dim.Fprintf(os.Stderr, "Plan saved: %s (dispatcher explain %s)\n", savedPath, result.Metadata.ID)
	}

	return nil
}

func runAIPlan(path string, constraints types.PlanConstraints) error {
	reg := target.NewRegistry()
	reg.LoadBuiltins()
	if err := reg.LoadUserConfig(); err != nil {
		color.New(color.Faint).Fprintf(os.Stderr, "warning: could not load user targets: %v\n", err)
	}

	hist, _ := cost.NewHistoryStore()
	cat := loadLiveCatalog(os.Stderr)

	tools := planner.NewToolRegistry(reg, hist, cat)

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	// Try aitelier backend; fall back to deterministic
	backend := planner.NewAtelierBackend(planner.AtelierConfig{ToolRegistry: tools})
	ctx := context.Background()

	var result *planner.PlanResult
	if err := backend.CheckAvailable(ctx); err == nil {
		bold.Fprintf(os.Stderr, "Planning with AI (%s via aitelier)...\n\n", backend.Model())
		p := planner.NewPlanner(backend, tools)
		var planErr error
		result, planErr = p.Plan(ctx, path, constraints)
		if planErr != nil {
			dim.Fprintf(os.Stderr, "AI planning failed: %v\nFalling back to deterministic...\n\n", planErr)
			result = nil
		}
	} else {
		dim.Fprintf(os.Stderr, "aitelier not available (%v)\n", err)
		dim.Fprintln(os.Stderr, "Falling back to deterministic mode...")
	}

	if result == nil {
		p := planner.NewPlanner(nil, tools)
		var err error
		result, err = p.DeterministicPlan(ctx, path, constraints)
		if err != nil {
			return fmt.Errorf("plan failed: %w", err)
		}
	}

	if jsonOutput() {
		return emitJSON(result)
	}

	// Print result
	bold.Fprintln(os.Stdout, result.Explanation)
	fmt.Fprintln(os.Stdout)

	if result.Recommendation != nil {
		bold.Fprintln(os.Stdout, "Recommended:")
		fmt.Fprintf(os.Stdout, "  Target: %s\n", result.Recommendation.Target)
		fmt.Fprintf(os.Stdout, "  Cost:   %s %s (%s)\n",
			formatCost(result.Recommendation.EstimatedCost.Value),
			result.Recommendation.EstimatedCost.Currency,
			result.Recommendation.EstimatedCost.Confidence)
	}

	if len(result.Alternatives) > 0 {
		fmt.Fprintln(os.Stdout)
		bold.Fprintln(os.Stdout, "Alternatives:")
		for _, alt := range result.Alternatives {
			fmt.Fprintf(os.Stdout, "  %s: %s %s\n", alt.Target, formatCost(alt.EstimatedCost.Value), alt.EstimatedCost.Currency)
		}
	}

	if len(result.Rejected) > 0 {
		fmt.Fprintln(os.Stdout)
		bold.Fprintln(os.Stdout, "Rejected:")
		for _, r := range result.Rejected {
			fmt.Fprintf(os.Stdout, "  %s: %s\n", r.Target, r.Reason)
		}
	}

	if len(result.Risks) > 0 {
		fmt.Fprintln(os.Stdout)
		bold.Fprintln(os.Stdout, "Risks:")
		for _, r := range result.Risks {
			fmt.Fprintf(os.Stdout, "  - %s\n", r.Description)
		}
	}

	dim.Fprintf(os.Stderr, "\nTools used: %v\n", result.ToolsUsed)

	return nil
}
