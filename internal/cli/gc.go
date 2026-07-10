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
	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/run"
)

var gcFlags struct {
	dryRun bool
	force  bool
}

// gcOrphanJSON / gcReport are the --json shape for gc.
type gcOrphanJSON struct {
	ResourceID string `json:"resourceId"`
	Provider   string `json:"provider"`
	RunID      string `json:"runId,omitempty"`
	Destroyed  bool   `json:"destroyed"`
	Error      string `json:"error,omitempty"`
}

type gcStandingJSON struct {
	ResourceID string  `json:"resourceId"`
	Provider   string  `json:"provider"`
	Kind       string  `json:"kind,omitempty"`
	MonthlyUSD float64 `json:"monthlyUsd,omitempty"`
}

type gcReport struct {
	Found     int              `json:"found"`
	Destroyed int              `json:"destroyed"`
	DryRun    bool             `json:"dryRun"`
	Orphans   []gcOrphanJSON   `json:"orphans"`
	Standing  []gcStandingJSON `json:"standing,omitempty"` // dispatcher-owned, kept (never reaped)
	External  []gcStandingJSON `json:"external,omitempty"` // not dispatcher-owned, listed only
}

var gcCmd = &cobra.Command{
	Use:         "gc",
	Annotations: map[string]string{supportsJSON: "true"},
	Short:       "Find and destroy orphaned cloud resources",
	Long: `Scans all configured cloud providers for VMs tagged by Dispatcher that no
longer have an active run, and destroys them.

Use --dry-run to preview what would be destroyed without acting — recommended
before running for real, especially with long-lived state directories.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		asJSON := jsonOutput()

		// Load all active (non-terminal) run IDs. A record that exists but fails
		// to parse is tracked separately: we must NOT treat its VM as an orphan,
		// since a corrupt record could belong to a live run — destroying it would
		// be irreversible data loss. Fail safe by protecting it instead.
		//
		// If the records can't even be enumerated, abort: an empty listing would
		// misclassify every live VM as an orphan and destroy the whole fleet.
		runIDs, err := run.ListRecords()
		if err != nil {
			return fmt.Errorf("cannot enumerate run records; refusing to GC (could destroy live runs): %w", err)
		}
		activeRuns := map[string]bool{}
		unreadableRuns := map[string]bool{}
		for _, id := range runIDs {
			rec, err := run.LoadRecord(id)
			switch {
			case err != nil:
				unreadableRuns[id] = true
			case !rec.State.IsTerminal():
				activeRuns[id] = true
			}
		}

		// Get all durable adapters
		adapters := durableAdaptersFn()
		if len(adapters) == 0 {
			if asJSON {
				return emitJSON(gcReport{DryRun: gcFlags.dryRun, Orphans: []gcOrphanJSON{}})
			}
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
		var standing []adapter.ResourceInfo
		var external []adapter.ResourceInfo

		for _, a := range adapters {
			resources, err := a.ListResources(ctx)
			if err != nil {
				if !asJSON {
					fmt.Fprintf(os.Stderr, "warning: cannot list resources for %s: %v\n", a.ID(), err)
				}
				continue
			}

			for _, res := range resources {
				// Hard boundary: anything dispatcher doesn't own is listed for
				// cost visibility but never touched — never reaped, never an
				// orphan, regardless of run-id.
				if !res.DispatcherOwned() {
					external = append(external, res)
					continue
				}
				// Standing infra: dispatcher-owned but tied to no run (a
				// driver-baked image, a shared disk). Report it, never reap it —
				// only run-scoped resources whose run is gone are orphans.
				if res.RunID == "" {
					standing = append(standing, res)
					continue
				}
				if activeRuns[res.RunID] {
					continue // active run, not an orphan
				}
				if unreadableRuns[res.RunID] {
					if !asJSON {
						red.Fprintf(os.Stderr, "  Skipping %s: run %s record is unreadable; refusing to destroy (could be live). Remove the run record to allow GC.\n", res.ResourceID, res.RunID)
					}
					continue
				}

				orphans = append(orphans, orphan{adapter: a, res: res})
				if !asJSON {
					bold.Fprintf(os.Stderr, "  Orphan: ")
					fmt.Fprintf(os.Stderr, "%s (%s", res.ResourceID, res.Provider)
					if !res.CreatedAt.IsZero() {
						fmt.Fprintf(os.Stderr, ", created %s", res.CreatedAt.Format("2006-01-02 15:04"))
					}
					if res.RunID != "" {
						fmt.Fprintf(os.Stderr, ", run %s", res.RunID)
					}
					fmt.Fprint(os.Stderr, ")")
					if res.MonthlyUSD > 0 {
						fmt.Fprintf(os.Stderr, " ~$%.2f/mo", res.MonthlyUSD)
					}
					fmt.Fprintln(os.Stderr)
				}
			}
		}

		if asJSON {
			// A prompt can't run with JSON output, so require an explicit intent —
			// but only when there's actually something to destroy. With zero
			// orphans, emit an empty report so polling callers don't have to
			// special-case the guard message.
			if len(orphans) > 0 && !gcFlags.dryRun && !gcFlags.force {
				return fmt.Errorf("gc --json requires --dry-run or --yes (interactive confirmation can't run with JSON output)")
			}
			report := gcReport{DryRun: gcFlags.dryRun, Orphans: []gcOrphanJSON{}}
			for _, o := range orphans {
				e := gcOrphanJSON{ResourceID: o.res.ResourceID, Provider: o.res.Provider, RunID: o.res.RunID}
				if !gcFlags.dryRun {
					if err := o.adapter.DestroyResource(ctx, o.res); err != nil {
						e.Error = err.Error()
					} else {
						e.Destroyed = true
						report.Destroyed++
						if o.res.RunID != "" {
							cloudvm.RemoveRunKeyFiles(o.res.RunID)
						}
					}
				}
				report.Orphans = append(report.Orphans, e)
			}
			report.Found = len(orphans)
			for _, s := range standing {
				report.Standing = append(report.Standing, gcStandingJSON{
					ResourceID: s.ResourceID, Provider: s.Provider,
					Kind: string(s.Kind), MonthlyUSD: s.MonthlyUSD,
				})
			}
			for _, e := range external {
				report.External = append(report.External, gcStandingJSON{
					ResourceID: e.ResourceID, Provider: e.Provider,
					Kind: string(e.Kind), MonthlyUSD: e.MonthlyUSD,
				})
			}
			return emitJSON(report)
		}

		ongoing := renderResourceSection("Standing dispatcher resources (kept, never reaped):", standing)
		ongoing += renderResourceSection("External resources (not dispatcher, listed only):", external)
		for _, o := range orphans {
			ongoing += o.res.MonthlyUSD
		}
		if ongoing > 0 {
			fmt.Fprintf(os.Stderr, "\nTotal ongoing ~$%.2f/mo across %d listed resource(s).\n",
				ongoing, len(standing)+len(external)+len(orphans))
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
			if err := o.adapter.DestroyResource(ctx, o.res); err != nil {
				red.Fprintf(os.Stderr, "  destroy %s failed: %v\n", o.res.ResourceID, err)
			} else {
				green.Fprintf(os.Stderr, "  destroyed %s\n", o.res.ResourceID)
				totalDestroyed++
				// Reclaim the per-run SSH key material the orphaned run left on
				// disk (the normal Cleanup path never ran for it). No-op for
				// targets without per-run keys (e.g. Kubernetes).
				if o.res.RunID != "" {
					cloudvm.RemoveRunKeyFiles(o.res.RunID)
				}
			}
		}

		fmt.Fprintf(os.Stderr, "\n%d orphan(s) found, %d destroyed.\n", len(orphans), totalDestroyed)
		return nil
	},
}

// renderResourceSection prints a titled list of resources with their monthly
// cost and returns the section's cost subtotal. A nil/empty list prints
// nothing and returns 0.
func renderResourceSection(title string, resources []adapter.ResourceInfo) float64 {
	if len(resources) == 0 {
		return 0
	}
	var subtotal float64
	fmt.Fprintf(os.Stderr, "\n%s\n", title)
	for _, r := range resources {
		subtotal += r.MonthlyUSD
		fmt.Fprintf(os.Stderr, "  %s (%s %s)", r.ResourceID, r.Provider, r.Kind)
		if r.MonthlyUSD > 0 {
			fmt.Fprintf(os.Stderr, " ~$%.2f/mo", r.MonthlyUSD)
		}
		fmt.Fprintln(os.Stderr)
	}
	return subtotal
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
