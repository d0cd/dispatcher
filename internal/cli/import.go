package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/target"
)

var importFlags struct {
	fromJSON       string
	fromTerraform  string
	binary         string
	allowSensitive bool
	dryRun         bool
}

var targetsImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import hosts as SSH targets from a dispatcher_targets source",
	Long: "Registers externally-provisioned hosts as dispatcher SSH targets, so the cost/\n" +
		"risk/approval/teardown layer can run jobs on infra you already own. The source is a\n" +
		"dispatcher_targets blob — {\"targets\":[{id,kind:\"ssh\",ssh:{host,user,port,key_file}}...]}.\n" +
		"\n" +
		"  --from-json <file|->     read the blob directly (- for stdin)\n" +
		"  --from-terraform <dir>   run `terraform output -json` and read the dispatcher_targets value\n" +
		"\n" +
		"Re-import reconciles add/update/remove against the previous import and never shadows\n" +
		"a hand-added target. Read-only with respect to your IaC state and resources.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		blob, err := resolveImportBlob(cmd)
		if errors.Is(err, target.ErrNoTargetsOutput) {
			fmt.Fprintln(os.Stdout, "No dispatcher_targets output found; nothing to import.")
			return nil
		}
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

// resolveImportBlob fetches the dispatcher_targets blob from the selected source.
func resolveImportBlob(cmd *cobra.Command) ([]byte, error) {
	switch {
	case importFlags.fromJSON != "" && importFlags.fromTerraform != "":
		return nil, fmt.Errorf("specify only one of --from-json / --from-terraform")
	case importFlags.fromJSON != "":
		if importFlags.fromJSON == "-" {
			return io.ReadAll(os.Stdin)
		}
		return os.ReadFile(importFlags.fromJSON)
	case importFlags.fromTerraform != "":
		binary := importFlags.binary
		if binary == "" {
			binary = detectTFBinary()
		}
		return target.FetchTerraformTargets(cmd.Context(), importFlags.fromTerraform,
			target.TerraformOptions{Binary: binary, AllowSensitive: importFlags.allowSensitive})
	default:
		return nil, fmt.Errorf("specify a source: --from-json <file|-> or --from-terraform <dir>")
	}
}

// detectTFBinary prefers terraform, falling back to tofu (OpenTofu).
func detectTFBinary() string {
	if _, err := exec.LookPath("terraform"); err == nil {
		return "terraform"
	}
	if _, err := exec.LookPath("tofu"); err == nil {
		return "tofu"
	}
	return "terraform"
}

func printImportDelta(label string, ids []string) {
	for _, id := range ids {
		fmt.Fprintf(os.Stdout, "  %-8s %s\n", label, id)
	}
}

func init() {
	targetsImportCmd.Flags().StringVar(&importFlags.fromJSON, "from-json", "", "path to a dispatcher_targets JSON file, or - for stdin")
	targetsImportCmd.Flags().StringVar(&importFlags.fromTerraform, "from-terraform", "", "path to a Terraform/OpenTofu workspace dir (reads `output -json`)")
	targetsImportCmd.Flags().StringVar(&importFlags.binary, "binary", "", "terraform binary to use (default: terraform, then tofu)")
	targetsImportCmd.Flags().BoolVar(&importFlags.allowSensitive, "allow-sensitive", false, "import even if the dispatcher_targets output is marked sensitive")
	targetsImportCmd.Flags().BoolVar(&importFlags.dryRun, "dry-run", false, "print what would be imported without writing")
	targetsCmd.AddCommand(targetsImportCmd)
}
