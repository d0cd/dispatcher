package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/target"
)

var importFlags struct {
	fromJSON       string
	fromTerraform  string
	binary         string
	workspace      string
	allowSensitive bool
	strict         bool
	yes            bool
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
		"Shows an add/update/remove plan and asks for confirmation (unless --yes). Re-import\n" +
		"reconciles against the previous import and never shadows a hand-added target.\n" +
		"Read-only with respect to your IaC state and resources.",
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

		plan, err := target.PlanImport(blob)
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "Import plan: %d add, %d update, %d remove\n",
			len(plan.Added), len(plan.Updated), len(plan.Removed))
		printImportDelta("add", plan.Added)
		printImportDelta("update", plan.Updated)
		printImportDelta("remove", plan.Removed)

		warns := target.KeyFileWarnings(plan.Targets())
		for _, w := range warns {
			color.New(color.FgYellow).Fprintf(os.Stderr, "  warning: %s\n", w)
		}
		if importFlags.strict && len(warns) > 0 {
			return fmt.Errorf("refusing to import under --strict: %d key_file warning(s)", len(warns))
		}

		if importFlags.dryRun {
			fmt.Fprintln(os.Stdout, "(dry run — nothing written)")
			return nil
		}
		if !plan.HasChanges() {
			fmt.Fprintln(os.Stdout, "Already up to date.")
			return nil
		}
		if !importFlags.yes && !confirmImport() {
			fmt.Fprintln(os.Stdout, "Aborted.")
			return nil
		}

		path, err := plan.Commit()
		if err != nil {
			return err
		}
		color.New(color.FgGreen).Fprintf(os.Stdout, "Imported targets → %s\n", path)
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
			target.TerraformOptions{Binary: binary, Workspace: importFlags.workspace, AllowSensitive: importFlags.allowSensitive})
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

// confirmImport prompts once on stdin. Returns true only on an explicit y/yes;
// an empty line, EOF, or a non-terminal stdin aborts.
func confirmImport() bool {
	fmt.Fprint(os.Stderr, "Apply this import? [y/N] ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil && input == "" {
		return false
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
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
	targetsImportCmd.Flags().StringVar(&importFlags.workspace, "workspace", "", "Terraform workspace to read (default: the selected one)")
	targetsImportCmd.Flags().BoolVar(&importFlags.allowSensitive, "allow-sensitive", false, "import even if the dispatcher_targets output is marked sensitive")
	targetsImportCmd.Flags().BoolVar(&importFlags.strict, "strict", false, "treat key_file warnings (missing/insecure) as errors")
	targetsImportCmd.Flags().BoolVarP(&importFlags.yes, "yes", "y", false, "skip the confirmation prompt")
	targetsImportCmd.Flags().BoolVar(&importFlags.dryRun, "dry-run", false, "print the plan without writing")
	targetsCmd.AddCommand(targetsImportCmd)
}
