package plan

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/d0cd/dispatcher/internal/types"
)

var (
	bold   = color.New(color.Bold)
	green  = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
	red    = color.New(color.FgRed)
	dim    = color.New(color.Faint)
)

// Print renders a plan to the given writer in terminal-friendly format.
func Print(p *types.Plan, w io.Writer) {
	printDetected(w, p)
	printRecommendation(w, p)
	printAlternatives(w, p)
	printRejected(w, p)
	printRisks(w, p)
	printApprovals(w, p)
	printValidation(w, p)
}

func printDetected(w io.Writer, p *types.Plan) {
	bold.Fprintln(w, "Detected:")
	fmt.Fprintf(w, "  %-18s %s\n", "Kind:", p.Workload.DetectedKind)
	fmt.Fprintf(w, "  %-18s %s\n", "Runtime:", p.Workload.Runtime)

	if len(p.Workload.Entrypoints) > 0 {
		fmt.Fprintf(w, "  %-18s %s\n", "Entrypoints:", strings.Join(p.Workload.Entrypoints, ", "))
	}
	if len(p.Workload.Ports) > 0 {
		portStrs := make([]string, len(p.Workload.Ports))
		for i, port := range p.Workload.Ports {
			portStrs[i] = fmt.Sprintf("%d", port)
		}
		fmt.Fprintf(w, "  %-18s %s\n", "Ports:", strings.Join(portStrs, ", "))
	}
	if p.Workload.Package.Dockerfile != "" {
		fmt.Fprintf(w, "  %-18s %s\n", "Dockerfile:", p.Workload.Package.Dockerfile)
	} else if p.Workload.Package.BuildRequired {
		fmt.Fprintf(w, "  %-18s generate from %s\n", "Package plan:", p.Workload.Package.BaseImage)
	}
	if p.Workload.Requirements.GPU.Required {
		fmt.Fprintf(w, "  %-18s %d x %s\n", "GPU:", p.Workload.Requirements.GPU.Count, p.Workload.Requirements.GPU.Framework)
	}
	fmt.Fprintln(w)
}

func printRecommendation(w io.Writer, p *types.Plan) {
	if p.Recommendation == nil {
		return
	}
	r := p.Recommendation

	bold.Fprintln(w, "Recommended:")
	green.Fprintf(w, "  %-18s %s\n", "Target:", r.Target)
	fmt.Fprintf(w, "  %-18s %s\n", "Runtime:", r.Runtime)
	fmt.Fprintf(w, "  %-18s $%.2f %s\n", "Estimated cost:", r.EstimatedCost.Value, r.EstimatedCost.Currency)
	fmt.Fprintf(w, "  %-18s %s\n", "Confidence:", r.EstimatedCost.Confidence)
	// Surface the safety rails — watchdog TTL and cost-excluded categories —
	// so the user knows the worst-case bill and what we're NOT counting.
	if p.Constraints.WatchdogTTL > 0 {
		fmt.Fprintf(w, "  %-18s %s (VM self-destructs if dispatcher dies)\n", "Watchdog TTL:", p.Constraints.WatchdogTTL)
	}
	if len(r.EstimatedCost.Exclusions) > 0 {
		fmt.Fprintf(w, "  %-18s %s\n", "Cost excludes:", strings.Join(r.EstimatedCost.Exclusions, ", "))
	}
	fmt.Fprintln(w)

	if len(r.Reason) > 0 {
		bold.Fprintln(w, "Why:")
		for _, reason := range r.Reason {
			fmt.Fprintf(w, "  - %s\n", reason)
		}
		fmt.Fprintln(w)
	}
}

func printAlternatives(w io.Writer, p *types.Plan) {
	if len(p.Alternatives) == 0 {
		return
	}

	bold.Fprintln(w, "Alternatives:")
	for _, alt := range p.Alternatives {
		yellow.Fprintf(w, "  %s", alt.Target)
		fmt.Fprintf(w, ": $%.2f/%s, %s\n", alt.EstimatedCost.Value, alt.EstimatedCost.Currency, alt.EstimatedCost.Confidence)
		for _, t := range alt.Tradeoff {
			dim.Fprintf(w, "    - %s\n", t)
		}
	}
	fmt.Fprintln(w)
}

func printRejected(w io.Writer, p *types.Plan) {
	if len(p.Rejected) == 0 {
		return
	}

	bold.Fprintln(w, "Rejected:")
	for _, r := range p.Rejected {
		red.Fprintf(w, "  %s", r.Target)
		fmt.Fprintf(w, ": %s\n", r.Reason)
	}
	fmt.Fprintln(w)
}

func printRisks(w io.Writer, p *types.Plan) {
	if len(p.Risks) == 0 {
		return
	}

	bold.Fprintln(w, "Risks:")
	for _, r := range p.Risks {
		yellow.Fprintf(w, "  - ")
		fmt.Fprintf(w, "%s\n", r.Description)
	}
	fmt.Fprintln(w)
}

func printApprovals(w io.Writer, p *types.Plan) {
	if len(p.RequiredApprovals) == 0 {
		return
	}

	bold.Fprintln(w, "Required approvals:")
	for _, a := range p.RequiredApprovals {
		fmt.Fprintf(w, "  - %s: %s\n", a.Name, a.Reason)
	}
	fmt.Fprintln(w)
}

func printValidation(w io.Writer, p *types.Plan) {
	bold.Fprintln(w, "Validation:")
	v := p.Validation
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

	for _, c := range checks {
		icon := green.Sprint("✓")
		switch c.status {
		case types.ValidationFail:
			icon = red.Sprint("✗")
		case types.ValidationWarn:
			icon = yellow.Sprint("!")
		case types.ValidationSkipped:
			icon = dim.Sprint("-")
		}
		fmt.Fprintf(w, "  %s %s\n", icon, c.name)
	}
	fmt.Fprintln(w)
}
