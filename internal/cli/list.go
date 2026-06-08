package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/types"
)

var listFlags struct {
	refresh bool
}

// staleThreshold is how long an ephemeral run can sit in a non-terminal
// state before list flags it as stale. Long enough that a normal workload
// finish-or-fail comfortably stays under it; short enough that a forgotten
// orphan stands out.
const staleThreshold = 6 * time.Hour

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all runs",
	Long: `Shows all saved runs with status, target, cost, and duration.

By default, list reads only the persisted run records — fast, no network.
A run in a non-terminal state with no recent activity is flagged STALE so
you can spot orphans (dispatcher killed mid-run, leaving the record stuck
in "running").

Pass --refresh to actively reconnect to each non-terminal durable run and
update its persisted state. Slower (one provider API call per run) but
authoritative.`,
	RunE: runList,
}

func init() {
	listCmd.Flags().BoolVar(&listFlags.refresh, "refresh", false,
		"reconnect to each non-terminal run, refresh live state, and persist")
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	ids, err := run.ListRecords()
	if err != nil {
		return fmt.Errorf("cannot list runs: %w", err)
	}

	if len(ids) == 0 {
		fmt.Fprintln(os.Stdout, "No runs found.")
		return nil
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.Faint)

	if listFlags.refresh {
		dim.Fprintln(os.Stderr, "Refreshing live state for non-terminal runs...")
		refreshNonTerminal(ids)
	}

	bold.Fprintf(os.Stdout, "%-14s %-16s %-16s %-10s %10s %10s\n",
		"RUN", "TARGET", "STATE", "LIFECYCLE", "COST", "DURATION")
	dim.Fprintln(os.Stdout, "─────────────────────────────────────────────────────────────────────────────────")

	stale := 0
	for _, id := range ids {
		rec, err := run.LoadRecord(id)
		if err != nil {
			continue
		}

		stateStr := string(rec.State)
		var stateColor *color.Color
		switch {
		case types.RunState(rec.State).IsFailure():
			stateColor = red
		case rec.State == types.RunStateCompleted:
			stateColor = green
		default:
			stateColor = yellow
			// Flag stale: non-terminal AND no progress for staleThreshold.
			// Reference point is LastHeartbeat for long-running, StartedAt
			// for ephemeral. No reference = no signal = don't flag.
			ref := rec.LastHeartbeat
			if ref.IsZero() {
				ref = rec.StartedAt
			}
			if !ref.IsZero() && time.Since(ref) > staleThreshold {
				stateStr = "STALE: " + stateStr
				stateColor = red
				stale++
			}
		}

		duration := ""
		if !rec.StartedAt.IsZero() {
			end := rec.FinishedAt
			if end.IsZero() {
				end = time.Now()
			}
			d := end.Sub(rec.StartedAt)
			switch {
			case d < time.Minute:
				duration = d.Round(time.Second).String()
			case d < time.Hour:
				duration = fmt.Sprintf("%.1fm", d.Minutes())
			default:
				duration = fmt.Sprintf("%.1fh", d.Hours())
			}
		}

		costStr := formatCost(rec.Cost.Value)

		lifecycle := string(rec.Lifecycle)
		if lifecycle == "" {
			lifecycle = "-"
		}

		fmt.Fprintf(os.Stdout, "%-14s %-16s ", rec.ID, rec.TargetID)
		stateColor.Fprintf(os.Stdout, "%-16s", stateStr)
		fmt.Fprintf(os.Stdout, " %-10s %10s %10s\n", lifecycle, costStr, duration)
	}

	if stale > 0 && !listFlags.refresh {
		fmt.Fprintln(os.Stdout)
		dim.Fprintf(os.Stdout, "%d run(s) appear stale (no progress in %s).\n",
			stale, staleThreshold)
		dim.Fprintln(os.Stdout, "Run `dispatcher list --refresh` to reconnect and update, or `dispatcher stop <id>` to force-cleanup.")
	}

	return nil
}

// refreshNonTerminal walks every non-terminal run with persisted handle
// state, reconnects via the adapter, queries live status, and if the
// live state has moved to terminal, saves the updated record. Errors are
// ignored per-run so one bad provider doesn't block the whole list.
func refreshNonTerminal(ids []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, id := range ids {
		rec, err := run.LoadRecord(id)
		if err != nil || rec.State.IsTerminal() || rec.HandleState == nil {
			continue
		}
		r, a, reconnErr := run.ReconnectToRun(ctx, id, adapterForTarget)
		if reconnErr != nil || a == nil || r.Handle == nil {
			continue
		}
		liveState, err := a.Status(ctx, r.Handle)
		if err != nil || liveState == rec.State || !liveState.IsTerminal() {
			continue
		}
		msg := "state refreshed via list --refresh"
		if fr, ok := a.(adapter.FailureReporter); ok {
			if fd := fr.FailureDetails(r.Handle); fd.Message != "" {
				msg = fd.Message
			}
		}
		r.SetError(liveState, errors.New(msg))
		if _, err := r.Save(); err != nil {
			dlog.L().Warn("list.refresh_save_failed", "run", id, "err", err.Error())
		}
	}
}
