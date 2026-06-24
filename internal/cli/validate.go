package cli

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/workload"
)

var validateCmd = &cobra.Command{
	Use:   "validate [dir]",
	Short: "Validate dispatcher.yaml without running anything",
	Long:  "Loads dispatcher.yaml from the given directory (default: current directory) and reports any schema or semantic errors, without planning or running a workload.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := "."
		if len(args) == 1 {
			dir = args[0]
		}
		cfg, err := workload.LoadConfig(dir)
		if err != nil {
			return err
		}
		if cfg == nil {
			return fmt.Errorf("no dispatcher.yaml found in %s (run `dispatcher init %s` to scaffold one)", dir, dir)
		}
		color.New(color.FgGreen).Fprintf(os.Stdout, "Configuration is valid.\n")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
}
