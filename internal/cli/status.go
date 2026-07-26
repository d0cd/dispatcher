package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/types"
)

var statusCmd = &cobra.Command{
	Use:         "status <run-id>",
	Annotations: map[string]string{supportsJSON: "true"},
	Short:       "Show the status of a run",
	Args:        cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStatusByID(args[0])
	},
}

// runStatusByID prints status for a single run id. Extracted so other
// commands (e.g. `recover --attach`) can refresh state without spawning
// a new dispatcher process.
func runStatusByID(id string) error {
	record, err := run.LoadRecord(id)
	if err != nil {
		return err
	}

	// For non-terminal runs with durable state, try live status — and
	// persist any terminal state we discover so the next `dispatcher list`
	// doesn't show "running" forever for a VM that's gone.
	// Per-run timeout matters because `dispatcher recover --attach` loops
	// over many runs; one hung provider must not block the rest.
	var renewedUntil time.Time
	if !record.State.IsTerminal() && record.HandleState != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		r, a, reconnErr := run.ReconnectToRun(ctx, id, adapterForTargetFn)
		if reconnErr == nil && a != nil && r.Handle != nil {
			statusOK := false
			if liveState, err := a.Status(ctx, r.Handle); err == nil {
				statusOK = true
				if liveState != record.State {
					record.State = liveState
					if liveState.IsTerminal() {
						if liveState.IsFailure() {
							msg := "state refreshed via live status check"
							if fr, ok := a.(adapter.FailureReporter); ok {
								if fd := fr.FailureDetails(r.Handle); fd.Message != "" {
									msg = fd.Message
								}
							}
							r.SetError(liveState, errors.New(msg))
						} else {
							r.MarkTerminal(liveState)
						}
						// Persist the runtime-scaled final cost before saving.
						// A self-terminated durable run never ran executeEphemeral's
						// FinalizeCost, so without this the record keeps its
						// pre-run cost and list/cost/bill undercount its spend.
						r.FinalizeCost()
						if _, err := r.Save(); err != nil {
							dlog.L().Warn("status.refresh_save_failed", "run", id, "err", err.Error())
						}
					}
				}
			}
			liveCost := r.ComputeLiveCost()
			if liveCost.Value > 0 {
				record.Cost = liveCost
			}
			// Checking on a still-running run counts as dispatcher watching it,
			// so push the watchdog deadline forward — but only when the live
			// status actually confirmed the run is still up. Best-effort: a
			// renewal failure must not fail `status`.
			if statusOK && !record.State.IsTerminal() {
				if deadline, renewErr := run.RenewWatchdog(ctx, a, r); renewErr == nil {
					renewedUntil = deadline
					if _, err := r.Save(); err != nil {
						dlog.L().Warn("status.renew_save_failed", "run", id, "err", err.Error())
					}
				} else {
					dlog.L().Warn("status.renew_failed", "run", id, "err", renewErr.Error())
				}
			}
		}
	}

	if jsonOutput() {
		return emitJSON(record)
	}

	bold := color.New(color.Bold)
	bold.Fprintf(os.Stdout, "Run: %s\n", record.ID)
	fmt.Fprintf(os.Stdout, "Plan:       %s\n", record.PlanID)
	fmt.Fprintf(os.Stdout, "Target:     %s\n", record.TargetID)
	fmt.Fprintf(os.Stdout, "Owner:      %s\n", record.Owner)

	if record.Lifecycle != "" {
		fmt.Fprintf(os.Stdout, "Lifecycle:  %s\n", record.Lifecycle)
	}

	stateColor := color.New(color.FgGreen)
	if types.RunState(record.State).IsFailure() {
		stateColor = color.New(color.FgRed)
	} else if !types.RunState(record.State).IsTerminal() {
		stateColor = color.New(color.FgYellow)
	}
	fmt.Fprintf(os.Stdout, "State:      ")
	stateColor.Fprintln(os.Stdout, record.State)

	if !renewedUntil.IsZero() {
		fmt.Fprintf(os.Stdout, "Watchdog:   extended until %s\n", renewedUntil.Format("2006-01-02 15:04:05 UTC"))
	}

	if !record.StartedAt.IsZero() {
		fmt.Fprintf(os.Stdout, "Started:    %s\n", record.StartedAt.Format("2006-01-02 15:04:05 UTC"))
	}
	if !record.FinishedAt.IsZero() {
		fmt.Fprintf(os.Stdout, "Finished:   %s\n", record.FinishedAt.Format("2006-01-02 15:04:05 UTC"))
		duration := record.FinishedAt.Sub(record.StartedAt)
		fmt.Fprintf(os.Stdout, "Duration:   %s\n", duration.Round(100*1e6))
	}
	if record.HandleID != "" {
		fmt.Fprintf(os.Stdout, "Handle:     %s\n", record.HandleID)
	}
	if att := attest.AttestationFromHandleState(record.HandleState); att != nil {
		printAttestation(att)
	}
	if record.Error != "" {
		color.New(color.FgRed).Fprintf(os.Stdout, "Error:      %s\n", record.Error)
	}
	if record.Cost.Value > 0 {
		fmt.Fprintf(os.Stdout, "Cost:       %s %s (%s)\n",
			formatCost(record.Cost.Value), record.Cost.Currency, record.Cost.Confidence)
	}

	// Surface the ongoing-spend warning here (not only on gc/bill) so a forgotten
	// still-billing run is caught during the check users run most. Local only.
	total, count := run.ActiveSpend()
	writeActiveSpendWarning(os.Stderr, total, count, spendWarnThreshold())

	return nil
}

// defaultSpendWarnUSD is the accumulated active-run cost above which status warns
// when DISPATCHER_WARN_OVER is unset.
const defaultSpendWarnUSD = 25.0

// spendWarnThreshold is the active-run spend (USD) above which status warns.
// DISPATCHER_WARN_OVER overrides the default; a non-positive value disables it.
func spendWarnThreshold() float64 {
	if v := os.Getenv("DISPATCHER_WARN_OVER"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return defaultSpendWarnUSD
}

// writeActiveSpendWarning warns when non-terminal runs' combined cost crosses the
// threshold. Silent otherwise, so normal status output stays clean.
func writeActiveSpendWarning(w io.Writer, total float64, count int, threshold float64) {
	if threshold <= 0 || total <= threshold {
		return
	}
	color.New(color.FgRed).Fprintf(w,
		"\nWARNING: %d active run(s) have accumulated ~$%.2f (over the $%.2f threshold). "+
			"Run `dispatcher gc` to check for leaked resources; set DISPATCHER_WARN_OVER to tune.\n",
		count, total, threshold)
}

// printAttestation renders a confidential run's TEE attestation verdict (R13):
// green "verified" with the proven type/measurement, or yellow "UNVERIFIED"
// with the reason (e.g. attestation: off).
func printAttestation(att *attest.AttestationResult) {
	head, c := "verified", color.New(color.FgGreen)
	if !att.Verified {
		head, c = "UNVERIFIED", color.New(color.FgYellow)
	}
	fmt.Fprintf(os.Stdout, "Attestation: ")
	if att.Type != "" {
		c.Fprintf(os.Stdout, "%s (%s)\n", head, att.Type)
	} else {
		c.Fprintf(os.Stdout, "%s\n", head)
	}
	if att.Measurement != "" {
		fmt.Fprintf(os.Stdout, "  Measurement: %s\n", att.Measurement)
	}
	if att.TCB != 0 {
		fmt.Fprintf(os.Stdout, "  TCB:         %d\n", att.TCB)
	}
	if att.Nonce != "" {
		fmt.Fprintf(os.Stdout, "  Nonce:       %s\n", att.Nonce)
	}
	if att.Verdict != "" {
		fmt.Fprintf(os.Stdout, "  Verdict:     %s\n", att.Verdict)
	}
}

var logsCmd = &cobra.Command{
	Use:   "logs <run-id>",
	Short: "Show logs for a run",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		record, err := run.LoadRecord(args[0])
		if err != nil {
			return err
		}

		// For non-terminal runs, try to reconnect and stream live logs
		if !record.State.IsTerminal() && record.HandleState != nil {
			ctx := context.Background()
			r, a, reconnErr := run.ReconnectToRun(ctx, args[0], adapterForTarget)
			if reconnErr == nil && a != nil && r.Handle != nil {
				fmt.Fprintf(os.Stderr, "Streaming logs for run %s on %s...\n\n", r.ID, r.TargetID)
				if err := a.Logs(ctx, r.Handle, os.Stdout); err != nil {
					fmt.Fprintf(os.Stderr, "\nLog streaming ended: %v\n", err)
				}
				return nil
			}
		}

		// Fallback: read from saved log file if available
		fmt.Fprintf(os.Stdout, "Run %s (%s on %s)\n\n", record.ID, record.State, record.TargetID)

		if record.LogFile != "" {
			data, err := os.ReadFile(record.LogFile)
			if err == nil && len(data) > 0 {
				os.Stdout.Write(data)
				return nil
			}
		}

		if record.State.IsTerminal() {
			color.New(color.Faint).Fprintln(os.Stdout, "No logs available for this run.")
			if record.Error != "" {
				fmt.Fprintf(os.Stdout, "\nError output:\n  %s\n", record.Error)
			}
		} else {
			fmt.Fprintln(os.Stdout, "Run is still in progress but reconnection is not available for this target.")
		}

		return nil
	},
}

var costCmd = &cobra.Command{
	Use:         "cost <run-id>",
	Annotations: map[string]string{supportsJSON: "true"},
	Short:       "Show cost tracking for a run",
	Args:        cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		record, err := run.LoadRecord(args[0])
		if err != nil {
			return err
		}

		// For non-terminal runs, try to compute live cost
		if !record.State.IsTerminal() && record.HandleState != nil {
			ctx := context.Background()
			r, _, reconnErr := run.ReconnectToRun(ctx, args[0], adapterForTarget)
			if reconnErr == nil && r.Plan != nil {
				record.Cost = r.ComputeLiveCost()
			}
		}

		if jsonOutput() {
			return emitJSON(record.Cost)
		}

		bold := color.New(color.Bold)
		bold.Fprintf(os.Stdout, "Run: %s\n", record.ID)
		fmt.Fprintf(os.Stdout, "Target:         %s\n", record.TargetID)
		fmt.Fprintf(os.Stdout, "State:          %s\n", record.State)

		est := record.Cost
		fmt.Fprintf(os.Stdout, "Estimated cost: %s %s\n", formatCost(est.Value), est.Currency)
		fmt.Fprintf(os.Stdout, "Confidence:     %s\n", est.Confidence)

		if !record.StartedAt.IsZero() && !record.FinishedAt.IsZero() {
			duration := record.FinishedAt.Sub(record.StartedAt)
			fmt.Fprintf(os.Stdout, "Runtime:        %s\n", duration.Round(100*1e6))
		}

		if len(est.Assumptions) > 0 {
			fmt.Fprintln(os.Stdout)
			bold.Fprintln(os.Stdout, "Assumptions:")
			for _, a := range est.Assumptions {
				fmt.Fprintf(os.Stdout, "  - %s\n", a)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(costCmd)
}
