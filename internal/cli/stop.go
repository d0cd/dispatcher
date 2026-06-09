package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/types"
)

var stopFlags struct {
	force bool
}

var stopCmd = &cobra.Command{
	Use:   "stop <run-id>",
	Short: "Stop a running workload and clean up resources",
	Long:  "Terminates a running workload, destroys cloud resources, and finalizes cost tracking.\n\nUse --force to finalize a stranded run whose record can no longer be reconnected (no handle state, provider unreachable). This marks the record terminal without attempting cleanup — destroy any leftover cloud resources with `dispatcher gc`.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		runID := args[0]

		r, a, err := run.ReconnectToRun(ctx, runID, adapterForTarget)
		if err != nil {
			if stopFlags.force {
				return forceStop(runID)
			}
			return fmt.Errorf("cannot connect to run: %w", err)
		}
		if a == nil {
			fmt.Fprintf(os.Stderr, "Run %s is already in terminal state: %s\n", r.ID, r.GetState())
			return nil
		}

		bold := color.New(color.Bold)
		bold.Fprintf(os.Stderr, "Stopping run %s on %s...\n", r.ID, r.TargetID)

		// Terminate the workload
		if r.Handle != nil {
			if err := a.Terminate(ctx, r.Handle); err != nil {
				fmt.Fprintf(os.Stderr, "warning: terminate failed: %v\n", err)
			}
		}

		// Transition to stopping
		_ = r.Transition(types.RunStateStopping)

		// Cleanup resources
		if r.Handle != nil {
			_ = r.Transition(types.RunStateCleaningUp)
			result, err := a.Cleanup(ctx, r.Handle)
			if err != nil || (result != nil && !result.Success) {
				r.SetError(types.RunStateCleanupFailed, fmt.Errorf("cleanup failed"))
				r.Save()
				color.New(color.FgRed).Fprintf(os.Stderr, "Cleanup failed for run %s\n", r.ID)
				return fmt.Errorf("cleanup failed")
			}
		}

		_ = r.Transition(types.RunStateCompleted)
		r.FinalizeCost()
		r.Save()

		color.New(color.FgGreen).Fprintf(os.Stderr, "Run %s stopped successfully.\n", r.ID)
		fmt.Fprintf(os.Stderr, "Final state: %s\n", r.GetState())
		if r.Cost.Value > 0 {
			fmt.Fprintf(os.Stderr, "Final cost:  %s %s\n", formatCost(r.Cost.Value), r.Cost.Currency)
		}

		return nil
	},
}

// forceStop finalizes a stranded run whose record can't be reconnected.
// It marks the record terminal without attempting Terminate/Cleanup so a
// run stuck in a non-terminal state (no handle, dead provider) stops
// lingering in `dispatcher list`.
func forceStop(runID string) error {
	record, err := run.LoadRecord(runID)
	if err != nil {
		return err
	}
	if record.State.IsTerminal() {
		fmt.Fprintf(os.Stderr, "Run %s is already in terminal state: %s\n", record.ID, record.State)
		return nil
	}

	r := run.RunFromRecord(record)
	r.SetError(types.RunStateCleanupFailed, errors.New("force-stopped: record could not be reconnected"))
	r.FinalizeCost()
	if _, err := r.Save(); err != nil {
		return fmt.Errorf("cannot save force-stopped run: %w", err)
	}

	color.New(color.FgYellow).Fprintf(os.Stderr, "Run %s force-stopped (record finalized without cleanup).\n", r.ID)
	fmt.Fprintf(os.Stderr, "Final state: %s\n", r.GetState())
	fmt.Fprintln(os.Stderr, "Any leftover cloud resources can be reclaimed with `dispatcher gc`.")
	return nil
}

func init() {
	stopCmd.Flags().BoolVar(&stopFlags.force, "force", false,
		"finalize a stranded run that can't be reconnected (skips cleanup)")
	rootCmd.AddCommand(stopCmd)
}
