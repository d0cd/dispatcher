package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/planner"
	"github.com/d0cd/dispatcher/internal/target"
)

var diagnoseCmd = &cobra.Command{
	Use:   "diagnose <run-id>",
	Short: "Diagnose a failed, stuck, or surprising run",
	Long:  "Loads the persisted run state and walks the AI diagnostician through it. Falls back to a deterministic summary when no LLM backend is configured.",
	Args:  cobra.ExactArgs(1),
	RunE:  runDiagnose,
}

func init() {
	rootCmd.AddCommand(diagnoseCmd)
}

func runDiagnose(cmd *cobra.Command, args []string) error {
	runID := args[0]

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

	backend := planner.NewAtelierBackend(planner.AtelierConfig{ToolRegistry: tools})
	ctx := context.Background()

	var (
		result *planner.DiagnoseResult
		err    error
	)
	if backendErr := backend.CheckAvailable(ctx); backendErr == nil {
		bold.Fprintf(os.Stderr, "Diagnosing with AI (%s via aitelier)...\n\n", backend.Model())
		p := planner.NewPlanner(backend, tools)
		result, err = p.Diagnose(ctx, runID)
		if err != nil {
			dim.Fprintf(os.Stderr, "AI diagnose failed: %v\nFalling back to deterministic...\n\n", err)
			result = nil
		}
	} else {
		dim.Fprintf(os.Stderr, "aitelier not available (%v)\nUsing deterministic diagnose.\n\n", backendErr)
	}

	if result == nil {
		p := planner.NewPlanner(nil, tools)
		result, err = p.DeterministicDiagnose(ctx, runID)
		if err != nil {
			return fmt.Errorf("diagnose failed: %w", err)
		}
	}

	printDiagnoseResult(result)
	return nil
}

func printDiagnoseResult(r *planner.DiagnoseResult) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	if r.Severity != "" {
		bold.Fprintf(os.Stdout, "[%s] ", r.Severity)
	}
	bold.Fprintln(os.Stdout, r.Explanation)

	if r.LikelyCause != "" {
		fmt.Fprintln(os.Stdout)
		bold.Fprintln(os.Stdout, "Likely cause:")
		fmt.Fprintf(os.Stdout, "  %s\n", r.LikelyCause)
	}

	if r.Recommendation != "" {
		fmt.Fprintln(os.Stdout)
		bold.Fprintln(os.Stdout, "Recommendation:")
		fmt.Fprintf(os.Stdout, "  %s\n", r.Recommendation)
	}

	if len(r.NextSteps) > 0 {
		fmt.Fprintln(os.Stdout)
		bold.Fprintln(os.Stdout, "Next steps:")
		for _, s := range r.NextSteps {
			fmt.Fprintf(os.Stdout, "  - %s\n", s)
		}
	}

	if len(r.ToolsUsed) > 0 {
		dim.Fprintf(os.Stderr, "\nTools used: %v\n", r.ToolsUsed)
	}
}
