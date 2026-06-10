package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/adapter"
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

var rootFlags struct {
	noColor  bool
	stateDir string
	json     bool
	output   string
}

var rootCmd = &cobra.Command{
	Use:     "dispatcher",
	Short:   "AI-assisted workload planner and runner",
	Long:    "Dispatcher plans, prices, and runs workloads across configured execution targets.\n\nRespects NO_COLOR and $DISPATCHER_HOME; --no-color and --state-dir override them.",
	Version: Version,
	// Runtime errors print their own actionable message; without this cobra
	// also dumps the full usage block, burying it.
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if rootFlags.noColor {
			color.NoColor = true
		}
		if rootFlags.stateDir != "" {
			os.Setenv("DISPATCHER_HOME", rootFlags.stateDir)
		}
		if rootFlags.json {
			rootFlags.output = "json"
		}
		if rootFlags.output != "text" && rootFlags.output != "json" {
			return fmt.Errorf("invalid --output %q: must be \"text\" or \"json\"", rootFlags.output)
		}
		// Reap orphaned plaintext-secret tempfiles left by a crashed run.
		_ = adapter.SweepStaleEnvFiles()
		return nil
	},
}

func Execute() error {
	rootCmd.Version = Version
	return rootCmd.Execute()
}

// emitJSON writes v as indented JSON to stdout. Used by commands in --json
// mode to emit their existing structured domain value.
func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func jsonOutput() bool { return rootFlags.output == "json" }

func init() {
	rootCmd.PersistentFlags().BoolVar(&rootFlags.noColor, "no-color", false, "disable colored output")
	rootCmd.PersistentFlags().StringVar(&rootFlags.stateDir, "state-dir", "",
		"override state directory (default: $DISPATCHER_HOME or ~/.dispatcher)")
	rootCmd.PersistentFlags().StringVar(&rootFlags.output, "output", "text", "output format: text, json")
	rootCmd.PersistentFlags().BoolVar(&rootFlags.json, "json", false, "shorthand for --output json")

	rootCmd.AddCommand(planCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(targetsCmd)
}
