package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/plan"
	"github.com/d0cd/dispatcher/internal/types"
)

var explainCmd = &cobra.Command{
	Use:   "explain <plan-id>",
	Short: "Explain a saved plan in detail",
	Long:  "Loads a previously generated plan and prints a detailed explanation of all decisions.",
	Args:  cobra.ExactArgs(1),
	RunE:  runExplain,
}

func init() {
	rootCmd.AddCommand(explainCmd)
}

func runExplain(cmd *cobra.Command, args []string) error {
	p, err := plan.Load(args[0])
	if err != nil {
		return err
	}

	w := os.Stdout
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	// Header
	bold.Fprintf(w, "Plan: %s\n", p.Metadata.ID)
	dim.Fprintf(w, "Created: %s by %s\n\n", p.Metadata.CreatedAt.Format("2006-01-02 15:04:05 UTC"), p.Metadata.CreatedBy)

	// Workload summary
	bold.Fprintln(w, "Workload Analysis:")
	fmt.Fprintf(w, "  Name:          %s\n", p.Workload.Name)
	fmt.Fprintf(w, "  Kind:          %s\n", p.Workload.DetectedKind)
	fmt.Fprintf(w, "  Runtime:       %s\n", p.Workload.Runtime)
	fmt.Fprintf(w, "  Source:        %s (%s)\n", p.Workload.Source.Path, p.Workload.Source.Type)
	if len(p.Workload.Entrypoints) > 0 {
		fmt.Fprintf(w, "  Entrypoints:   %s\n", strings.Join(p.Workload.Entrypoints, ", "))
	}
	if len(p.Workload.Ports) > 0 {
		portStrs := make([]string, len(p.Workload.Ports))
		for i, port := range p.Workload.Ports {
			portStrs[i] = fmt.Sprintf("%d", port)
		}
		fmt.Fprintf(w, "  Ports:         %s\n", strings.Join(portStrs, ", "))
	}
	if p.Workload.Requirements.GPU.Required {
		fmt.Fprintf(w, "  GPU:           %d x %s (%s)\n",
			p.Workload.Requirements.GPU.Count,
			p.Workload.Requirements.GPU.Model,
			p.Workload.Requirements.GPU.Framework)
	}
	if p.Workload.Package.Dockerfile != "" {
		fmt.Fprintf(w, "  Dockerfile:    %s\n", p.Workload.Package.Dockerfile)
	} else if p.Workload.Package.BaseImage != "" {
		fmt.Fprintf(w, "  Base image:    %s (auto-generated)\n", p.Workload.Package.BaseImage)
	}
	fmt.Fprintln(w)

	// Constraints
	bold.Fprintln(w, "Constraints:")
	fmt.Fprintf(w, "  Optimize for:  %s\n", p.Constraints.OptimizeFor)
	if p.Constraints.MaxEstimatedCostUSD > 0 {
		fmt.Fprintf(w, "  Max cost:      $%.2f\n", p.Constraints.MaxEstimatedCostUSD)
	}
	if p.Constraints.TargetName != "" {
		fmt.Fprintf(w, "  Target:        %s\n", p.Constraints.TargetName)
	}
	if p.Constraints.RequireGPU != "" {
		fmt.Fprintf(w, "  GPU:           %s\n", p.Constraints.RequireGPU)
	}
	fmt.Fprintln(w)

	// Full plan output
	plan.Print(p, w)

	// Execution steps detail
	if len(p.ExecutionSteps) > 0 {
		bold.Fprintln(w, "Execution steps:")
		for i, step := range p.ExecutionSteps {
			fmt.Fprintf(w, "  %d. %s\n", i+1, step)
		}
		fmt.Fprintln(w)
	}

	// Secrets found
	if len(p.Workload.Secrets) > 0 {
		bold.Fprintln(w, "Secrets detected:")
		for _, s := range p.Workload.Secrets {
			fmt.Fprintf(w, "  - %s (%s) in %s\n", s.Name, s.Kind, s.Location)
		}
		fmt.Fprintln(w)
	}

	// Data dependencies
	if len(p.Workload.Data) > 0 {
		bold.Fprintln(w, "Data dependencies:")
		for _, d := range p.Workload.Data {
			fmt.Fprintf(w, "  - %s: %s\n", d.Kind, d.Details)
		}
		fmt.Fprintln(w)
	}

	// Cost assumptions
	if p.Recommendation != nil {
		est := p.Recommendation.EstimatedCost
		bold.Fprintln(w, "Cost assumptions:")
		for _, a := range est.Assumptions {
			fmt.Fprintf(w, "  - %s\n", a)
		}
		if len(est.Exclusions) > 0 {
			bold.Fprintln(w, "Cost exclusions:")
			for _, e := range est.Exclusions {
				fmt.Fprintf(w, "  - %s\n", e)
			}
		}
		fmt.Fprintln(w)
	}

	printValidationDetail(w, p.Validation)

	return nil
}

func printValidationDetail(w *os.File, v types.ValidationResult) {
	bold := color.New(color.Bold)
	bold.Fprintln(w, "Validation detail:")
	checks := []struct {
		name   string
		status types.ValidationStatus
	}{
		{"Schema", v.Schema},
		{"Package build", v.PackageBuild},
		{"Target capabilities", v.TargetCapabilities},
		{"Credentials", v.Credentials},
		{"Quota", v.Quota},
		{"Network", v.Network},
		{"Policy", v.Policy},
		{"Cost estimate", v.CostEstimate},
		{"Cleanup plan", v.CleanupPlan},
	}

	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.Faint)

	for _, c := range checks {
		var icon, label string
		switch c.status {
		case types.ValidationPass:
			icon = green.Sprint("✓")
			label = "pass"
		case types.ValidationFail:
			icon = red.Sprint("✗")
			label = "FAIL"
		case types.ValidationWarn:
			icon = yellow.Sprint("!")
			label = "warning"
		case types.ValidationSkipped:
			icon = dim.Sprint("-")
			label = "skipped"
		}
		fmt.Fprintf(w, "  %s %-22s %s\n", icon, c.name, label)
	}
	fmt.Fprintln(w)
}
