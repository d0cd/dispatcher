package cli

import (
	"github.com/spf13/cobra"
)

// Version is the dispatcher release tag. Overridden at build time via -ldflags
// (e.g. -X github.com/d0cd/dispatcher/internal/cli.Version=v0.1.0).
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:     "dispatcher",
	Short:   "AI-assisted workload planner and runner",
	Long:    "Dispatcher plans, prices, and runs workloads across configured execution targets.",
	Version: Version,
}

func Execute() error {
	rootCmd.Version = Version
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(planCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(targetsCmd)
}
