package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/target"
	"github.com/d0cd/dispatcher/internal/types"
)

var targetsCmd = &cobra.Command{
	Use:   "targets",
	Short: "Manage execution targets",
}

func loadRegistry() *target.Registry {
	r := target.NewRegistry()
	r.LoadBuiltins()
	_ = r.LoadUserConfig()
	return r
}

// availableTargetIDs renders the registry's target IDs as a comma-separated
// list, so a "not found" error can point the user at what they can actually use.
func availableTargetIDs(registry *target.Registry) string {
	targets := registry.List()
	ids := make([]string, len(targets))
	for i, t := range targets {
		ids[i] = t.ID
	}
	if len(ids) == 0 {
		return "(none configured)"
	}
	return strings.Join(ids, ", ")
}

var targetsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured targets",
	RunE: func(cmd *cobra.Command, args []string) error {
		registry := loadRegistry()

		targets := registry.List()
		if len(targets) == 0 {
			fmt.Println("No targets configured.")
			return nil
		}

		bold := color.New(color.Bold)
		for _, t := range targets {
			status := color.GreenString("enabled")
			if !t.Enabled {
				status = color.RedString("disabled")
			}
			bold.Fprintf(os.Stdout, "  %-20s", t.ID)
			fmt.Fprintf(os.Stdout, " %-14s %s\n", t.Kind, status)
		}
		return nil
	},
}

var addFlags struct {
	kind    string
	host    string
	user    string
	port    int
	keyFile string
	enabled bool
}

var targetsAddCmd = &cobra.Command{
	Use:   "add <target-id>",
	Short: "Add a new target",
	Long:  "Adds a new target to your user configuration (~/.dispatcher/targets/).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]

		kind := types.TargetKind(addFlags.kind)
		switch kind {
		case types.TargetKindDocker, types.TargetKindSSH, types.TargetKindKubernetes,
			types.TargetKindCloudVM:
			// valid
		default:
			return fmt.Errorf("unknown target kind %q (valid: docker, ssh, kubernetes, cloud-vm)", addFlags.kind)
		}

		t := types.TargetConfig{
			ID:           id,
			Kind:         kind,
			Enabled:      addFlags.enabled,
			Capabilities: defaultCapabilitiesForKind(kind),
		}

		if kind == types.TargetKindSSH {
			if addFlags.host == "" {
				return fmt.Errorf("ssh target requires --host")
			}
			t.SSH = &types.SSHTargetConfig{
				Host:    addFlags.host,
				User:    addFlags.user,
				Port:    addFlags.port,
				KeyFile: addFlags.keyFile,
			}
		}

		path, err := target.SaveTarget(t)
		if err != nil {
			return err
		}

		color.New(color.FgGreen).Fprintf(os.Stdout, "Target %q added.\n", id)
		fmt.Fprintf(os.Stdout, "Config: %s\n", path)
		fmt.Fprintln(os.Stdout, "Edit the YAML file to customize capabilities.")
		return nil
	},
}

var targetsRemoveCmd = &cobra.Command{
	Use:     "remove <target-id>",
	Aliases: []string{"rm"},
	Short:   "Remove a target you added",
	Long:    "Removes a user-added target file from ~/.dispatcher/targets/. Builtins and dispatcher.yaml targets are not removable.",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		path, err := target.DeleteTarget(id)
		if err != nil {
			return err
		}
		color.New(color.FgGreen).Fprintf(os.Stdout, "Target %q removed.\n", id)
		fmt.Fprintf(os.Stdout, "Deleted: %s\n", path)
		return nil
	},
}

var targetsDoctorCmd = &cobra.Command{
	Use:   "doctor <target-id>",
	Short: "Check target health and connectivity",
	Long:  "Validates that a target is reachable and its capabilities are available.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]

		registry := loadRegistry()
		t, ok := registry.Get(id)
		if !ok {
			return fmt.Errorf("target %q not found; available targets: %s", id, availableTargetIDs(registry))
		}

		bold := color.New(color.Bold)
		green := color.New(color.FgGreen)
		red := color.New(color.FgRed)
		yellow := color.New(color.FgYellow)

		bold.Fprintf(os.Stdout, "Checking target: %s (%s)\n\n", t.ID, t.Kind)

		checks := runDoctorChecks(t)
		allPassed := true
		for _, c := range checks {
			var icon *color.Color
			switch c.status {
			case "pass":
				icon = green
			case "fail":
				icon = red
				allPassed = false
			case "warn":
				icon = yellow
			case "skip":
				icon = color.New(color.Faint)
			}
			icon.Fprintf(os.Stdout, "  %s ", statusIcon(c.status))
			fmt.Fprintf(os.Stdout, "%-30s %s\n", c.name, c.detail)
		}

		fmt.Fprintln(os.Stdout)
		if allPassed {
			green.Fprintln(os.Stdout, "All checks passed.")
		} else {
			red.Fprintln(os.Stdout, "Some checks failed. See details above.")
		}

		return nil
	},
}

type doctorCheck struct {
	name   string
	status string // pass, fail, warn, skip
	detail string
}

func runDoctorChecks(t types.TargetConfig) []doctorCheck {
	var checks []doctorCheck

	// Enabled check
	if t.Enabled {
		checks = append(checks, doctorCheck{"Enabled", "pass", ""})
	} else {
		checks = append(checks, doctorCheck{"Enabled", "warn", "target is disabled"})
	}

	ctx := context.Background()

	switch t.Kind {
	case types.TargetKindDocker:
		checks = append(checks, checkDocker(ctx)...)
	case types.TargetKindLocalVM:
		checks = append(checks, checkLima(ctx)...)
	case types.TargetKindSSH:
		checks = append(checks, checkSSH(ctx, t))
	case types.TargetKindKubernetes:
		checks = append(checks, checkKubernetes(ctx)...)
	default:
		checks = append(checks, doctorCheck{"Connectivity", "skip", "no connectivity check for " + string(t.Kind)})
	}

	// Capability checks
	if len(t.Capabilities.WorkloadKinds) > 0 {
		kinds := make([]string, len(t.Capabilities.WorkloadKinds))
		for i, k := range t.Capabilities.WorkloadKinds {
			kinds[i] = string(k)
		}
		checks = append(checks, doctorCheck{"Workload kinds", "pass", strings.Join(kinds, ", ")})
	} else {
		checks = append(checks, doctorCheck{"Workload kinds", "warn", "no workload kinds defined"})
	}

	if t.Capabilities.Resources.GPU.Supported {
		models := strings.Join(t.Capabilities.Resources.GPU.Models, ", ")
		if models == "" {
			models = "any"
		}
		checks = append(checks, doctorCheck{"GPU support", "pass", models})
	} else {
		checks = append(checks, doctorCheck{"GPU support", "skip", "not supported"})
	}

	return checks
}

func checkDocker(ctx context.Context) []doctorCheck {
	var checks []doctorCheck

	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	output, err := cmd.Output()
	if err != nil {
		checks = append(checks, doctorCheck{"Docker daemon", "fail", "docker is not available"})
		return checks
	}
	version := strings.TrimSpace(string(output))
	checks = append(checks, doctorCheck{"Docker daemon", "pass", "version " + version})

	// Check docker can run containers
	cmd = exec.CommandContext(ctx, "docker", "run", "--rm", "hello-world")
	if err := cmd.Run(); err != nil {
		checks = append(checks, doctorCheck{"Docker run", "fail", "cannot run containers"})
	} else {
		checks = append(checks, doctorCheck{"Docker run", "pass", "hello-world succeeded"})
	}

	return checks
}

// checkSSH probes connectivity to a configured SSH target. With no host it
// stays a skip; with a host it runs a real non-interactive `ssh ... true`.
func checkSSH(ctx context.Context, t types.TargetConfig) doctorCheck {
	if t.SSH == nil || t.SSH.Host == "" {
		return doctorCheck{"SSH connectivity", "skip", "requires host configuration"}
	}

	port := t.SSH.Port
	if port == 0 {
		port = 22
	}
	dest := t.SSH.Host
	if t.SSH.User != "" {
		dest = t.SSH.User + "@" + t.SSH.Host
	}

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=accept-new",
	}
	if t.SSH.KeyFile != "" {
		args = append(args, "-i", t.SSH.KeyFile)
	}
	args = append(args, "-p", strconv.Itoa(port), dest, "true")

	if err := exec.CommandContext(ctx, "ssh", args...).Run(); err != nil {
		return doctorCheck{"SSH connectivity", "fail", fmt.Sprintf("cannot reach %s: %v", dest, err)}
	}
	return doctorCheck{"SSH connectivity", "pass", "reachable at " + dest}
}

func checkKubernetes(ctx context.Context) []doctorCheck {
	var checks []doctorCheck

	cmd := exec.CommandContext(ctx, "kubectl", "cluster-info")
	if err := cmd.Run(); err != nil {
		checks = append(checks, doctorCheck{"Kubernetes cluster", "fail", "kubectl cluster-info failed"})
		return checks
	}
	checks = append(checks, doctorCheck{"Kubernetes cluster", "pass", "cluster reachable"})

	// Check namespace access
	cmd = exec.CommandContext(ctx, "kubectl", "auth", "can-i", "create", "pods")
	output, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(output)) != "yes" {
		checks = append(checks, doctorCheck{"Pod creation", "fail", "cannot create pods"})
	} else {
		checks = append(checks, doctorCheck{"Pod creation", "pass", ""})
	}

	return checks
}

func checkLima(ctx context.Context) []doctorCheck {
	var checks []doctorCheck
	// Distinguish "binary missing" (truly skip) from "binary present but
	// failing" (real problem worth surfacing as a fail).
	if _, err := exec.LookPath("limactl"); err != nil {
		checks = append(checks, doctorCheck{"Lima", "skip", "limactl not installed"})
		return checks
	}
	// Modern limactl (>=1.0) uses `--version`; older builds used `version`
	// as a subcommand. Try the new form first, fall back so we don't
	// false-fail on older installs.
	output, err := exec.CommandContext(ctx, "limactl", "--version").Output()
	if err != nil {
		output, err = exec.CommandContext(ctx, "limactl", "version").Output()
	}
	if err != nil {
		checks = append(checks, doctorCheck{"Lima", "fail",
			"limactl present but neither --version nor version subcommand worked: " + err.Error()})
		return checks
	}
	version := strings.TrimSpace(string(output))
	checks = append(checks, doctorCheck{"Lima", "pass", version})
	return checks
}

func statusIcon(status string) string {
	switch status {
	case "pass":
		return "✓"
	case "fail":
		return "✗"
	case "warn":
		return "!"
	case "skip":
		return "-"
	}
	return "?"
}

func defaultCapabilitiesForKind(kind types.TargetKind) types.Capabilities {
	switch kind {
	case types.TargetKindDocker:
		return types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindScript, types.WorkloadKindJob, types.WorkloadKindContainer, types.WorkloadKindService},
			Resources:     types.ResourceCapability{CPU: true, Memory: true},
			Accounting:    types.AccountingCapability{CostEstimate: true, RateCard: "local"},
			Isolation:     types.IsolationCapability{Levels: []string{"container"}},
			Observability: types.ObservabilityCapability{Logs: true, Artifacts: true},
		}
	case types.TargetKindSSH:
		return types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindScript, types.WorkloadKindJob, types.WorkloadKindContainer, types.WorkloadKindService},
			Resources:     types.ResourceCapability{CPU: true, Memory: true},
			Networking:    types.NetworkingCapability{PublicEndpoint: true, PrivateVPCAccess: true},
			Accounting:    types.AccountingCapability{CostEstimate: true, RateCard: "ssh"},
			Isolation:     types.IsolationCapability{Levels: []string{"process", "container"}},
			Observability: types.ObservabilityCapability{Logs: true, Artifacts: true},
		}
	case types.TargetKindKubernetes:
		return types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindJob, types.WorkloadKindContainer, types.WorkloadKindService, types.WorkloadKindGPUJob},
			Resources:     types.ResourceCapability{CPU: true, Memory: true, GPU: types.GPUCapability{Supported: true}},
			Networking:    types.NetworkingCapability{PublicEndpoint: true, PrivateVPCAccess: true},
			Accounting:    types.AccountingCapability{CostEstimate: true, RateCard: "internal"},
			Isolation:     types.IsolationCapability{Levels: []string{"container", "dedicated-node"}},
			Observability: types.ObservabilityCapability{Logs: true, Metrics: true, Artifacts: true},
		}
	default:
		return types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindScript, types.WorkloadKindJob},
			Resources:     types.ResourceCapability{CPU: true, Memory: true},
			Accounting:    types.AccountingCapability{CostEstimate: true},
			Observability: types.ObservabilityCapability{Logs: true},
		}
	}
}

func init() {
	targetsAddCmd.Flags().StringVar(&addFlags.kind, "kind", "docker", "target kind: docker, ssh, kubernetes, cloud-vm")
	targetsAddCmd.Flags().StringVar(&addFlags.host, "host", "", "hostname for SSH targets")
	targetsAddCmd.Flags().StringVar(&addFlags.user, "user", "", "username for SSH targets")
	targetsAddCmd.Flags().IntVar(&addFlags.port, "port", 22, "port for SSH targets")
	targetsAddCmd.Flags().StringVar(&addFlags.keyFile, "key-file", "", "private key path for SSH targets")
	targetsAddCmd.Flags().BoolVar(&addFlags.enabled, "enabled", true, "whether the target is enabled")

	targetsCmd.AddCommand(targetsListCmd)
	targetsCmd.AddCommand(targetsAddCmd)
	targetsCmd.AddCommand(targetsRemoveCmd)
	targetsCmd.AddCommand(targetsDoctorCmd)
}
