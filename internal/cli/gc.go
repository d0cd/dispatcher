package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/run"
)

var gcFlags struct {
	dryRun bool
	force  bool
}

var gcCmd = &cobra.Command{
	Use:   "gc",
	Short: "Find and destroy orphaned cloud resources",
	Long: `Scans all configured cloud providers for VMs tagged by Dispatcher that no
longer have an active run, and destroys them.

Use --dry-run to preview what would be destroyed without acting — recommended
before running for real, especially with long-lived state directories.`,
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
		adapters := durableAdaptersFn()
		if len(adapters) == 0 {
			fmt.Fprintln(os.Stderr, "No cloud VM adapters configured.")
			return nil
		}

		bold := color.New(color.Bold)
		red := color.New(color.FgRed)
		green := color.New(color.FgGreen)

		type orphan struct {
			adapter adapter.DurableAdapter
			res     adapter.ResourceInfo
		}
		var orphans []orphan

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

				orphans = append(orphans, orphan{adapter: a, res: res})
				bold.Fprintf(os.Stderr, "  Orphan: ")
				fmt.Fprintf(os.Stderr, "%s (%s", res.ResourceID, res.Provider)
				if !res.CreatedAt.IsZero() {
					fmt.Fprintf(os.Stderr, ", created %s", res.CreatedAt.Format("2006-01-02 15:04"))
				}
				if res.RunID != "" {
					fmt.Fprintf(os.Stderr, ", run %s", res.RunID)
				}
				fmt.Fprintln(os.Stderr, ")")
			}
		}

		if len(orphans) == 0 {
			green.Fprintln(os.Stderr, "No orphaned resources found.")
			return nil
		}

		if gcFlags.dryRun {
			fmt.Fprintf(os.Stderr, "\n%d orphan(s) found. Run without --dry-run to destroy.\n", len(orphans))
			return nil
		}

		if !gcFlags.force && !confirmDestroy(len(orphans)) {
			fmt.Fprintln(os.Stderr, "Aborted; nothing destroyed.")
			return nil
		}

		totalDestroyed := 0
		for _, o := range orphans {
			if err := o.adapter.DestroyResource(ctx, o.res.ResourceID); err != nil {
				red.Fprintf(os.Stderr, "  destroy %s failed: %v\n", o.res.ResourceID, err)
			} else {
				green.Fprintf(os.Stderr, "  destroyed %s\n", o.res.ResourceID)
				totalDestroyed++
			}
		}

		fmt.Fprintf(os.Stderr, "\n%d orphan(s) found, %d destroyed.\n", len(orphans), totalDestroyed)
		return nil
	},
}

// confirmDestroy prompts once on stdin before gc destroys orphans. Returns
// true only on an explicit y/yes; an empty line, EOF, or anything else aborts.
func confirmDestroy(n int) bool {
	fmt.Fprintf(os.Stderr, "Destroy %d orphan(s)? [y/N] ", n)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil && input == "" {
		return false
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

func init() {
	gcCmd.Flags().BoolVar(&gcFlags.dryRun, "dry-run", false, "list orphans without destroying them")
	gcCmd.Flags().BoolVarP(&gcFlags.force, "yes", "y", false, "skip confirmation prompt")
	rootCmd.AddCommand(gcCmd)
}

// durableAdaptersFn is the seam gc uses to discover durable adapters; tests
// override it to inject fakes.
var durableAdaptersFn = durableAdapters

// durableAdapters returns cloud VM adapters whose CLIs are actually installed.
func durableAdapters() []adapter.DurableAdapter {
	cliChecks := map[string]string{
		"lima-vm":    "limactl",
		"kubernetes": "kubectl",
		"hetzner-vm": "hcloud",
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
