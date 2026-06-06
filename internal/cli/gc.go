package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/run"
)

var gcFlags struct {
	dryRun bool
}

var gcCmd = &cobra.Command{
	Use:   "gc",
	Short: "Find and destroy orphaned cloud resources",
	Long:  "Scans all configured cloud providers for VMs tagged by Dispatcher that no longer have an active run.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Load all active (non-terminal) run IDs
		runIDs, _ := run.ListRecords()
		activeRuns := map[string]bool{}
		for _, id := range runIDs {
			rec, err := run.LoadRecord(id)
			if err == nil && !rec.State.IsTerminal() {
				activeRuns[id] = true
			}
		}

		// Get all durable adapters
		adapters := durableAdapters()
		if len(adapters) == 0 {
			fmt.Fprintln(os.Stderr, "No cloud VM adapters configured.")
			return nil
		}

		bold := color.New(color.Bold)
		red := color.New(color.FgRed)
		green := color.New(color.FgGreen)
		dim := color.New(color.Faint)

		totalOrphans := 0
		totalDestroyed := 0

		for _, a := range adapters {
			resources, err := a.ListResources(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: cannot list resources for %s: %v\n", a.ID(), err)
				continue
			}

			for _, res := range resources {
				if res.RunID != "" && activeRuns[res.RunID] {
					continue // active run, not an orphan
				}

				totalOrphans++
				bold.Fprintf(os.Stderr, "  Orphan: ")
				fmt.Fprintf(os.Stderr, "%s (%s", res.ResourceID, res.Provider)
				if !res.CreatedAt.IsZero() {
					fmt.Fprintf(os.Stderr, ", created %s", res.CreatedAt.Format("2006-01-02 15:04"))
				}
				if res.RunID != "" {
					fmt.Fprintf(os.Stderr, ", run %s", res.RunID)
				}
				fmt.Fprintln(os.Stderr, ")")

				if gcFlags.dryRun {
					dim.Fprintln(os.Stderr, "    (dry run, not destroying)")
					continue
				}

				if err := a.DestroyResource(ctx, res.ResourceID); err != nil {
					red.Fprintf(os.Stderr, "    destroy failed: %v\n", err)
				} else {
					green.Fprintln(os.Stderr, "    destroyed")
					totalDestroyed++
				}
			}
		}

		if totalOrphans == 0 {
			green.Fprintln(os.Stderr, "No orphaned resources found.")
		} else if gcFlags.dryRun {
			fmt.Fprintf(os.Stderr, "\n%d orphan(s) found. Run without --dry-run to destroy.\n", totalOrphans)
		} else {
			fmt.Fprintf(os.Stderr, "\n%d orphan(s) found, %d destroyed.\n", totalOrphans, totalDestroyed)
		}

		return nil
	},
}

func init() {
	gcCmd.Flags().BoolVar(&gcFlags.dryRun, "dry-run", false, "list orphans without destroying them")
	rootCmd.AddCommand(gcCmd)
}

// durableAdapters returns cloud VM adapters whose CLIs are actually installed.
func durableAdapters() []adapter.DurableAdapter {
	cliChecks := map[string]string{
		"lima-vm":      "limactl",
		"kubernetes":   "kubectl",
		"hetzner-vm":  "hcloud",
		"aws-vm":     "aws",
		"gcp-vm":     "gcloud",
		"azure-vm":   "az",
	}
	var result []adapter.DurableAdapter
	for id, cli := range cliChecks {
		if _, err := exec.LookPath(cli); err != nil {
			continue // CLI not installed, skip silently
		}
		a, err := adapterForTarget(id)
		if err != nil {
			continue
		}
		if d, ok := a.(adapter.DurableAdapter); ok {
			result = append(result, d)
		}
	}
	return result
}
