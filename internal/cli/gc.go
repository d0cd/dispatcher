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
	"github.com/d0cd/dispatcher/internal/types"
)

var gcFlags struct {
	dryRun          bool
	force           bool
	warnOver        float64
	allowEmptyStore bool
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
	Found       int              `json:"found"`
	Destroyed   int              `json:"destroyed"`
	DryRun      bool             `json:"dryRun"`
	Orphans     []gcOrphanJSON   `json:"orphans"`
	Standing    []gcStandingJSON `json:"standing,omitempty"`    // dispatcher-owned, kept (never reaped)
	External    []gcStandingJSON `json:"external,omitempty"`    // not dispatcher-owned, listed only
	MonthlyUSD  float64          `json:"monthlyUsdTotal"`       // total ongoing cost across all listed resources
	CostWarning bool             `json:"costWarning,omitempty"` // MonthlyUSD exceeds the warn threshold
	ScopeNote   string           `json:"scopeNote,omitempty"`   // caveat when a cloud's scan is confined to one RG/project
}

// scopeLimitNote returns a caveat when the adapter set includes a provider whose
// GC scan is confined to one scope — Azure (the configured resource group) and
// GCP (the configured project). Leaked dispatcher resources outside that scope
// aren't enumerated, so an empty gc doesn't mean "no leaks anywhere". Returns ""
// when no scope-limited provider is present.
func scopeLimitNote(adapterIDs []string) string {
	azure, gcp := false, false
	for _, id := range adapterIDs {
		switch id {
		case "azure-vm":
			azure = true
		case "gcp-vm":
			gcp = true
		}
	}
	var scopes []string
	if azure {
		scopes = append(scopes, "Azure (configured resource group only)")
	}
	if gcp {
		scopes = append(scopes, "GCP (configured project only)")
	}
	if len(scopes) == 0 {
		return ""
	}
	return "Note: GC scanned one scope per cloud — " + strings.Join(scopes, ", ") +
		". Dispatcher resources in other resource groups or projects are not listed here."
}

var gcCmd = &cobra.Command{
	Use:         "gc",
	Annotations: map[string]string{supportsJSON: "true"},
	Short:       "Find and destroy orphaned cloud resources",
	Long: `Scans all configured cloud providers for billable resources and reports their
ongoing cost. Resources are classified three ways:

  orphan   - tagged by Dispatcher, its run is gone      -> destroyed
  standing - tagged by Dispatcher, tied to no run       -> listed, kept
  external - not tagged by Dispatcher                   -> listed only

Only resources Dispatcher owns (tag dispatcher=true) are ever destroyed;
everything else is listed purely for cost visibility.

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
		// Cloud VMs are tagged with the PLAN id (the adapter is handed a Plan, not
		// a run), so res.RunID is a plan id — protect by plan id, not the run
		// record's own id, or the guard never matches and gc reaps live VMs. A
		// corrupt record is protected too: recover its plan id from the raw file,
		// and if even that fails, refuse to reap any run-scoped resource (a
		// destroy is irreversible; the record could belong to a live run).
		activeRuns := map[string]bool{}
		unreadableRuns := map[string]bool{}
		unrecoverable := false
		for _, id := range runIDs {
			rec, err := run.LoadRecord(id)
			switch {
			case err != nil:
				if pid := run.RecoverPlanID(id); pid != "" {
					unreadableRuns[pid] = true
				} else {
					unrecoverable = true
				}
			case !rec.State.IsTerminal():
				activeRuns[rec.PlanID] = true
			case rec.State == types.RunStateArtifactFailed:
				// The executor deliberately preserved this VM for output recovery
				// (its watchdog TTL is the lease). Protect it from reaping so gc
				// doesn't destroy the outputs the operator still needs; the watchdog
				// (or `dispatcher stop`) reclaims it.
				activeRuns[rec.PlanID] = true
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
				if unrecoverable {
					// A run record couldn't be read AND its plan id couldn't be
					// recovered, so this run-scoped resource might belong to it.
					// Fail closed — never risk destroying a live run's VM.
					if !asJSON {
						red.Fprintf(os.Stderr, "  Skipping %s: a run record is unreadable and its plan id is unrecoverable; refusing to destroy any run-scoped resource. Remove the corrupt record to allow GC.\n", res.ResourceID)
					}
					continue
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
					fmt.Fprintln(os.Stderr, resourceCostLabel(res))
				}
			}
		}

		// Empty-store safety guard. run.ListRecords() does NOT error on a fresh or
		// mispointed state dir — it silently returns zero records — so the enumerate-
		// error guard above doesn't cover it. If the store has zero records yet
		// adapters report dispatcher-owned resources referencing run IDs, those "run
		// IDs" are absent from the store: almost always a misconfigured state dir
		// (wrong $DISPATCHER_HOME / user / cwd) rather than genuine orphans — and
		// reaping would destroy the whole live fleet. Refuse unless overridden.
		// Dry-run is exempt (it never destroys and shows the user the problem); the
		// JSON path without --yes is exempt too (it errors out before destroying).
		adapterIDs := make([]string, 0, len(adapters))
		for _, a := range adapters {
			adapterIDs = append(adapterIDs, a.ID())
		}
		scopeNote := scopeLimitNote(adapterIDs)

		willDestroy := !gcFlags.dryRun && (!asJSON || gcFlags.force)
		if willDestroy && !gcFlags.allowEmptyStore && len(runIDs) == 0 && len(orphans) > 0 {
			return fmt.Errorf("refusing to GC: run store has 0 records but %d dispatcher-owned resource(s) reference run IDs — the state dir is likely misconfigured (check $DISPATCHER_HOME / --state-dir). Re-run with --allow-empty-store if the store is genuinely empty and these are real orphans", len(orphans))
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
			for _, o := range orphans {
				report.MonthlyUSD += o.res.MonthlyUSD
			}
			for _, s := range standing {
				report.MonthlyUSD += s.MonthlyUSD
			}
			for _, e := range external {
				report.MonthlyUSD += e.MonthlyUSD
			}
			report.CostWarning = gcFlags.warnOver > 0 && report.MonthlyUSD > gcFlags.warnOver
			report.ScopeNote = scopeNote
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
		if gcFlags.warnOver > 0 && ongoing > gcFlags.warnOver {
			red.Fprintf(os.Stderr, "\nWARNING: ongoing cost ~$%.2f/mo exceeds the $%.2f/mo threshold (--warn-over).\n",
				ongoing, gcFlags.warnOver)
		}
		if scopeNote != "" {
			color.New(color.Faint).Fprintf(os.Stderr, "\n%s\n", scopeNote)
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

// resourceCostLabel formats a resource's monthly cost for display. A running
// instance is never free, so an unknown (uncatalogued) instance cost renders as
// "cost unknown" rather than an empty/implied-$0 — the costliest thing to leak
// must never look free. Other kinds with no cost render nothing.
func resourceCostLabel(r adapter.ResourceInfo) string {
	if r.MonthlyUSD > 0 {
		return fmt.Sprintf(" ~$%.2f/mo", r.MonthlyUSD)
	}
	if r.Kind == adapter.ResourceInstance {
		return " (cost unknown)"
	}
	return ""
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
		fmt.Fprintf(os.Stderr, "  %s (%s %s)%s\n", r.ResourceID, r.Provider, r.Kind, resourceCostLabel(r))
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
	gcCmd.Flags().Float64Var(&gcFlags.warnOver, "warn-over", 10.0, "warn loudly when total ongoing cost exceeds this USD/mo (0 disables)")
	gcCmd.Flags().BoolVar(&gcFlags.allowEmptyStore, "allow-empty-store", false, "permit reaping when the run store has zero records (bypasses the misconfigured-state-dir guard)")
	rootCmd.AddCommand(gcCmd)
}

// durableAdaptersFn is the seam gc uses to discover durable adapters; tests
// override it to inject fakes.
var durableAdaptersFn = durableAdapters

// gcProviderCLIs maps every durable target gc can reap to the CLI whose presence
// gates it. Every provisionable cloud-VM target MUST appear here — a target that
// `dispatcher run` can create but gc can't discover leaks orphaned billing VMs
// invisibly (TestGCDiscoversAllCloudTargets guards this).
var gcProviderCLIs = map[string]string{
	"lima-vm":    "limactl",
	"kubernetes": "kubectl",
	"hetzner-vm": "hcloud",
	"aws-vm":     "aws",
	"gcp-vm":     "gcloud",
	"azure-vm":   "az",
	"oci-vm":     "oci",
}

// gcProviderEnv maps REST/env-gated durable targets (no vendor CLI) to the env
// var whose presence enables gc discovery. Lambda Cloud is HTTP-native, so CLI
// presence can't gate it — the API key does. Same leak guarantee as
// gcProviderCLIs: a provisionable target absent from both maps leaks silently.
var gcProviderEnv = map[string]string{
	"lambda-vm": "DISPATCHER_LAMBDA_API_KEY",
}

// durableAdapters returns cloud VM adapters whose CLI (or gating env) is present.
func durableAdapters() []adapter.DurableAdapter {
	var result []adapter.DurableAdapter
	add := func(id string) {
		a, err := adapterForTarget(id)
		if err != nil {
			return
		}
		if d, ok := a.(adapter.DurableAdapter); ok {
			result = append(result, d)
		}
	}
	for id, cli := range gcProviderCLIs {
		if _, err := exec.LookPath(cli); err != nil {
			continue // CLI not installed, skip silently
		}
		add(id)
	}
	for id, env := range gcProviderEnv {
		if os.Getenv(env) == "" {
			continue // not configured, skip
		}
		add(id)
	}
	return result
}
