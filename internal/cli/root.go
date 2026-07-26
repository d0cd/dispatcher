package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/secrets"
	"github.com/d0cd/dispatcher/internal/workload"
)

// Version is the dispatcher release tag. Overridden at build time via -ldflags
// (e.g. -X github.com/d0cd/dispatcher/internal/cli.Version=v0.1.0). When left at
// the default, resolveVersion recovers the tag from the module build info, so
// `go install ...@v0.2.0` (which does not run ldflags) still reports v0.2.0.
var Version = "dev"

// resolveVersion picks the most specific version available: an explicit -ldflags
// value wins; otherwise the module version embedded by `go install` is used; a
// local `go build` (module version "(devel)") falls back to the ldflags default.
func resolveVersion(ldflags string, info *debug.BuildInfo, ok bool) string {
	if ldflags != "dev" {
		return ldflags
	}
	if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return ldflags
}

// ExitError carries an explicit process exit code from a command back to
// main(). Tests see it as a normal error; the production main wrapper reads
// .Code and calls os.Exit accordingly. Set AlreadyPrinted when the command has
// already presented the failure to the user (e.g. run's "Run failed:" block),
// so main() doesn't print it a second time.
type ExitError struct {
	Code           int
	Err            error
	AlreadyPrinted bool
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// ResolveExitError maps a top-level command error to a process exit code and
// the message main() should print. message is empty when there is nothing to
// print (no error, or the command already surfaced it). Cobra is configured
// with SilenceErrors so main() is the single place errors reach the terminal —
// without this, an error from a command would exit non-zero with no output.
func ResolveExitError(err error) (code int, message string) {
	if err == nil {
		return 0, ""
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		if ee.AlreadyPrinted {
			return ee.Code, ""
		}
		return ee.Code, ee.Error()
	}
	return 1, err.Error()
}

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
	// main() is the single place errors reach the terminal (via
	// ResolveExitError), so cobra must not also print them. This keeps
	// per-command output (e.g. run's "Run failed:") from being duplicated and
	// guarantees plain errors are surfaced rather than exiting silently.
	SilenceErrors: true,
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
		if jsonOutput() && cmd.Annotations[supportsJSON] != "true" {
			return fmt.Errorf("--json is not supported by %q (supported: plan, audit, status, cost, list, bill, history, recover, gc)", cmd.CommandPath())
		}
		// Register user-global secret-resolution commands so any command that builds
		// a provider (plan/run/gc/status) can resolve credentials; a per-project
		// dispatcher.yaml layers on top. A malformed global config fails closed.
		opCfg, err := workload.LoadOperatorConfig()
		if err != nil {
			return err
		}
		secrets.SetGlobal(opCfg.Secrets)
		// Reap orphaned plaintext-secret tempfiles left by a crashed run.
		_ = adapter.SweepStaleEnvFiles()
		return nil
	},
}

func Execute() error {
	info, ok := debug.ReadBuildInfo()
	rootCmd.Version = resolveVersion(Version, info, ok)
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

// supportsJSON is the command annotation marking commands that honor --json.
// PersistentPreRunE rejects --json on any command without it, so the flag is
// never silently ignored.
const supportsJSON = "supportsJSON"

func init() {
	rootCmd.PersistentFlags().BoolVar(&rootFlags.noColor, "no-color", false, "disable colored output")
	rootCmd.PersistentFlags().StringVar(&rootFlags.stateDir, "state-dir", "",
		"override state directory (default: $DISPATCHER_HOME or ~/.dispatcher)")
	rootCmd.PersistentFlags().StringVar(&rootFlags.output, "output", "text", "output format: text, json")
	rootCmd.PersistentFlags().BoolVar(&rootFlags.json, "json", false, "shorthand for --output json")

	rootCmd.AddCommand(planCmd)
	rootCmd.AddCommand(confidentialCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(targetsCmd)
}
