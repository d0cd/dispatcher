package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/target"
)

var importFlags struct {
	fromJSON string
	dryRun   bool
}

var targetsImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import hosts as SSH targets from a dispatcher_targets source",
	Long: "Reads a dispatcher_targets blob — a {\"targets\":[{id,kind:\"ssh\",ssh:{host,user,port,key_file}}...]}\n" +
		"object — and registers its hosts as dispatcher SSH targets, so the cost/risk/approval/\n" +
		"teardown layer can run jobs on infra you already provisioned. Re-import reconciles\n" +
		"add/update/remove against the previous import. Pipe `terraform output -json` (the\n" +
		"value of a dispatcher_targets output) in via --from-json -.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if importFlags.fromJSON == "" {
			return fmt.Errorf("specify a source: --from-json <file|->")
		}
		blob, err := readImportSource(importFlags.fromJSON)
		if err != nil {
			return err
		}

		if importFlags.dryRun {
			targets, err := target.ParseDispatcherTargets(blob)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Would import %d target(s):\n", len(targets))
			for _, t := range targets {
				fmt.Fprintf(os.Stdout, "  + %-20s %s@%s\n", t.ID, t.SSH.User, t.SSH.Host)
			}
			return nil
		}

		res, err := target.ImportFromJSON(blob)
		if err != nil {
			return err
		}
		color.New(color.FgGreen).Fprintf(os.Stdout, "Imported targets → %s\n", res.Path)
		printImportDelta("added", res.Added)
		printImportDelta("updated", res.Updated)
		printImportDelta("removed", res.Removed)
		return nil
	},
}

func readImportSource(src string) ([]byte, error) {
	if src == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(src)
}

func printImportDelta(label string, ids []string) {
	for _, id := range ids {
		fmt.Fprintf(os.Stdout, "  %-8s %s\n", label, id)
	}
}

func init() {
	targetsImportCmd.Flags().StringVar(&importFlags.fromJSON, "from-json", "", "path to a dispatcher_targets JSON file, or - for stdin")
	targetsImportCmd.Flags().BoolVar(&importFlags.dryRun, "dry-run", false, "print what would be imported without writing")
	targetsCmd.AddCommand(targetsImportCmd)
}
