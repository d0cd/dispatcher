package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/planner"
	"github.com/d0cd/dispatcher/internal/target"
)

var auditCmd = &cobra.Command{
	Use:         "audit [path]",
	Annotations: map[string]string{supportsJSON: "true"},
	Short:       "Audit a workload for risks before running it (defaults to current directory)",
	Long:        "Inspects the workload and surfaces concerns (cost, secrets, reliability, compliance) before execution. Uses the AI auditor when aitelier is available, otherwise a deterministic ruleset.\n\nIf path is omitted, the current directory is used.\n\nExit codes:\n  0  ready / concerns (no blockers)\n  2  blocked (one or more critical findings)\n  3  AI returned non-conforming output (re-run or use deterministic)",
	Args:        cobra.MaximumNArgs(1),
	RunE:        runAudit,
}

func init() {
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) error {
	raw := "."
	if len(args) > 0 {
		raw = args[0]
	}
	path, err := filepath.Abs(raw)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", raw, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot read %s (does it exist?): %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path must be a directory; %s is a file", path)
	}

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

	var result *planner.AuditResult
	if backendErr := backend.CheckAvailable(ctx); backendErr == nil {
		bold.Fprintf(os.Stderr, "Auditing with AI (%s via aitelier)...\n\n", backend.Model())
		p := planner.NewPlanner(backend, tools)
		r, err := p.Audit(ctx, path)
		if err != nil {
			dim.Fprintf(os.Stderr, "AI audit failed: %v\nFalling back to deterministic...\n\n", err)
		} else {
			result = r
		}
	} else {
		dim.Fprintf(os.Stderr, "aitelier not available (%v)\nUsing deterministic audit.\n\n", backendErr)
	}

	if result == nil {
		p := planner.NewPlanner(nil, tools)
		r, err := p.DeterministicAudit(ctx, path)
		if err != nil {
			return fmt.Errorf("audit failed: %w", err)
		}
		result = r
	}

	if jsonOutput() {
		if err := emitJSON(result); err != nil {
			return err
		}
	} else {
		printAuditResult(result)
	}
	switch result.Verdict {
	case "blocked":
		return &ExitError{Code: 2, Err: fmt.Errorf("audit verdict: blocked")}
	case "unknown":
		// Distinct exit code so CI can tell "AI failed to produce structured
		// output" apart from "audit passed" and "audit blocked".
		return &ExitError{Code: 3, Err: fmt.Errorf("audit verdict: unknown (AI returned non-conforming output)")}
	}
	return nil
}

func printAuditResult(r *planner.AuditResult) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	bold.Fprintln(os.Stdout, r.Summary)
	fmt.Fprintf(os.Stdout, "Verdict: %s\n", verdictColored(r.Verdict))

	if len(r.Findings) > 0 {
		fmt.Fprintln(os.Stdout)
		for _, f := range r.Findings {
			fmt.Fprintf(os.Stdout, "[%s] %s — %s\n", severityColored(f.Severity), f.Category, f.Title)
			if f.Detail != "" {
				fmt.Fprintf(os.Stdout, "  %s\n", f.Detail)
			}
			if f.Suggestion != "" {
				dim.Fprintf(os.Stdout, "  → %s\n", f.Suggestion)
			}
		}
	}

	if len(r.ToolsUsed) > 0 {
		dim.Fprintf(os.Stderr, "\nTools used: %v\n", r.ToolsUsed)
	}
}

func severityColored(sev string) string {
	switch sev {
	case "critical":
		return color.New(color.FgRed, color.Bold).Sprint(sev)
	case "warning":
		return color.New(color.FgYellow).Sprint(sev)
	case "info":
		return color.New(color.FgCyan).Sprint(sev)
	}
	return sev
}

func verdictColored(v string) string {
	switch v {
	case "ready":
		return color.New(color.FgGreen, color.Bold).Sprint(v)
	case "concerns":
		return color.New(color.FgYellow, color.Bold).Sprint(v)
	case "blocked":
		return color.New(color.FgRed, color.Bold).Sprint(v)
	case "unknown":
		return color.New(color.FgMagenta, color.Bold).Sprint(v + " (AI returned prose, not structured findings — re-run to retry)")
	}
	return v
}
