package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/types"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all runs",
	Long:  "Shows all saved runs with their status, target, cost, and duration.",
	RunE: func(cmd *cobra.Command, args []string) error {
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

		bold.Fprintf(os.Stdout, "%-14s %-16s %-16s %-10s %10s %10s\n",
			"RUN", "TARGET", "STATE", "LIFECYCLE", "COST", "DURATION")
		dim.Fprintln(os.Stdout, "─────────────────────────────────────────────────────────────────────────────────")

		for _, id := range ids {
			rec, err := run.LoadRecord(id)
			if err != nil {
				continue
			}

			// State with color
			stateStr := string(rec.State)
			var stateColor *color.Color
			if types.RunState(rec.State).IsFailure() {
				stateColor = red
			} else if rec.State == types.RunStateCompleted {
				stateColor = green
			} else {
				stateColor = yellow
			}

			// Duration
			duration := ""
			if !rec.StartedAt.IsZero() {
				end := rec.FinishedAt
				if end.IsZero() {
					end = time.Now()
				}
				d := end.Sub(rec.StartedAt)
				if d < time.Minute {
					duration = d.Round(time.Second).String()
				} else if d < time.Hour {
					duration = fmt.Sprintf("%.1fm", d.Minutes())
				} else {
					duration = fmt.Sprintf("%.1fh", d.Hours())
				}
			}

			// Cost
			costStr := ""
			if rec.Cost.Value > 0 {
				costStr = fmt.Sprintf("$%.2f", rec.Cost.Value)
			} else if rec.Cost.Currency != "" {
				costStr = "$0.00"
			}

			// Lifecycle
			lifecycle := string(rec.Lifecycle)
			if lifecycle == "" {
				lifecycle = "-"
			}

			fmt.Fprintf(os.Stdout, "%-14s %-16s ", rec.ID, rec.TargetID)
			stateColor.Fprintf(os.Stdout, "%-16s", stateStr)
			fmt.Fprintf(os.Stdout, " %-10s %10s %10s\n", lifecycle, costStr, duration)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
