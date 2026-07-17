package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/cost"
)

var historyCmd = &cobra.Command{
	Use:         "history",
	Annotations: map[string]string{supportsJSON: "true"},
	Short:       "Show historical run data and statistics",
	Long:        "Displays statistics from past runs used to improve cost and duration estimates.",
	RunE: func(cmd *cobra.Command, args []string) error {
		history, err := cost.NewHistoryStore()
		if err != nil {
			return fmt.Errorf("cannot load history: %w", err)
		}

		if jsonOutput() {
			return emitJSON(struct {
				Entries int                         `json:"entries"`
				Targets map[string]cost.TargetStats `json:"targets"`
			}{history.Len(), history.AllStats()})
		}

		if history.Len() == 0 {
			fmt.Fprintln(os.Stdout, "No run history yet. Run some workloads to build up data.")
			return nil
		}

		bold := color.New(color.Bold)
		dim := color.New(color.Faint)

		bold.Fprintf(os.Stdout, "Run history: %d entries\n\n", history.Len())

		stats := history.AllStats()
		if len(stats) == 0 {
			return nil
		}

		bold.Fprintf(os.Stdout, "%-18s %6s %6s %10s %12s\n",
			"TARGET", "RUNS", "OK", "AVG COST", "AVG DURATION")
		dim.Fprintln(os.Stdout, "──────────────────────────────────────────────────────────────")

		for target, s := range stats {
			duration := "-"
			if s.AvgDuration > 0 {
				if s.AvgDuration < time.Minute {
					duration = s.AvgDuration.Round(time.Second).String()
				} else {
					duration = fmt.Sprintf("%.1fm", s.AvgDuration.Minutes())
				}
			}
			costStr := "-"
			if s.AvgCost > 0 {
				costStr = formatCost(s.AvgCost)
			} else if s.SuccessRuns > 0 {
				costStr = "$0.00"
			}
			fmt.Fprintf(os.Stdout, "%-18s %6d %6d %10s %12s\n",
				target, s.TotalRuns, s.SuccessRuns, costStr, duration)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(historyCmd)
}
