package cli

import (
	"github.com/spf13/cobra"
)

// Version is the dispatcher release tag. Overridden at build time via -ldflags
// (e.g. -X github.com/d0cd/dispatcher/internal/cli.Version=v0.1.0).
var Version = "dev"

// ExitError carries an explicit process exit code from a command back to
// main(). Tests see it as a normal error; the production main wrapper reads
// .Code and calls os.Exit accordingly.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

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
