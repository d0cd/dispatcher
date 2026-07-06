package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/run"
)

var traceCmd = &cobra.Command{
	Use:   "trace <run-id>",
	Short: "Emit a Chrome/Perfetto timeline of a run's phases",
	Long: "Emit the run's phase timeline (provision, run, collect, teardown, ...) as\n" +
		"Chrome Trace Event Format JSON. Pipe to a file and open it in chrome://tracing\n" +
		"or https://ui.perfetto.dev to see where a run's wall-clock time went.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTraceByID(args[0])
	},
}

func runTraceByID(id string) error {
	rec, err := run.LoadRecord(id)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(run.BuildTrace(rec), "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(data))
	return nil
}

func init() {
	rootCmd.AddCommand(traceCmd)
}
