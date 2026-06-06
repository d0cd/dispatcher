package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/plan"
	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/types"
)

var runFlags struct {
	target   string
	optimize string
	maxCost  float64
	timeout  string
	gpu      string
	yes      bool
}

var runCmd = &cobra.Command{
	Use:   "run [path]",
	Short: "Plan and execute a workload",
	Long:  "Generates a plan for the workload at the given path, then executes it on the recommended target.",
	Args:  cobra.ExactArgs(1),
	RunE:  runRun,
}

func init() {
	runCmd.Flags().StringVar(&runFlags.target, "target", "", "run on a specific target")
	runCmd.Flags().StringVar(&runFlags.optimize, "optimize", "cost", "optimize for: cost, speed")
	runCmd.Flags().Float64Var(&runFlags.maxCost, "max-cost", 0, "maximum estimated cost in USD")
	runCmd.Flags().StringVar(&runFlags.gpu, "gpu", "", "GPU requirement (e.g. 1, h100:1)")
	runCmd.Flags().StringVar(&runFlags.timeout, "timeout", "", "maximum run duration (e.g. 30m, 2h)")
	runCmd.Flags().BoolVarP(&runFlags.yes, "yes", "y", false, "auto-approve all policy gates")
	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	path, err := filepath.Abs(args[0])
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("path %s is not a valid directory", path)
	}

	optimizeFor := types.OptimizeCost
	if runFlags.optimize == "speed" {
		optimizeFor = types.OptimizeSpeed
	}

	var maxDuration time.Duration
	if runFlags.timeout != "" {
		d, err := time.ParseDuration(runFlags.timeout)
		if err != nil {
			return fmt.Errorf("invalid timeout %q: %w", runFlags.timeout, err)
		}
		maxDuration = d
	}

	constraints := types.PlanConstraints{
		TargetScope:         "workspace-defaults",
		OptimizeFor:         optimizeFor,
		MaxEstimatedCostUSD: runFlags.maxCost,
		MaxDuration:         maxDuration,
		RequireGPU:          runFlags.gpu,
		TargetName:          runFlags.target,
	}

	// Generate plan
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	bold.Fprintln(os.Stderr, "Planning...")
	p, err := plan.Build(path, constraints)
	if err != nil {
		return fmt.Errorf("plan failed: %w", err)
	}

	// Save plan
	if _, err := plan.Save(p); err != nil {
		dim.Fprintf(os.Stderr, "warning: could not save plan: %v\n", err)
	}

	if p.Recommendation == nil {
		return fmt.Errorf("no recommendation in plan")
	}

	// Show summary
	fmt.Fprintf(os.Stderr, "Using plan:        %s\n", p.Metadata.ID)
	fmt.Fprintf(os.Stderr, "Target:            %s\n", p.Recommendation.Target)
	fmt.Fprintf(os.Stderr, "Estimated cost:    $%.2f %s\n", p.Recommendation.EstimatedCost.Value, p.Recommendation.EstimatedCost.Currency)

	if len(p.RequiredApprovals) > 0 {
		color.New(color.FgYellow).Fprintln(os.Stderr, "Approvals required:")
		for _, a := range p.RequiredApprovals {
			fmt.Fprintf(os.Stderr, "  - %s: %s\n", a.Name, a.Reason)
		}
		fmt.Fprintln(os.Stderr)
	}

	// Select adapter
	a, err := adapterForTarget(p.Recommendation.Target)
	if err != nil {
		return err
	}

	// Create and execute run
	r := run.NewRun(p)
	executor := run.NewExecutor(a)
	if !runFlags.yes {
		executor.SetApprovalFunc(terminalApproval)
	}

	bold.Fprintf(os.Stderr, "\nRun: %s\n", r.ID)
	fmt.Fprintln(os.Stderr, "Status: running")
	fmt.Fprintln(os.Stderr)

	ctx := context.Background()
	if maxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, maxDuration)
		defer cancel()
		dim.Fprintf(os.Stderr, "Timeout: %s\n\n", maxDuration)
	}

	// Create log file and tee stdout to it
	logWriter, logCloser := setupRunLogFile(r)
	if logCloser != nil {
		defer logCloser.Close()
	}

	if err := executor.Execute(ctx, r, logWriter); err != nil {
		// Save run state even on failure
		if _, saveErr := r.Save(); saveErr != nil {
			dim.Fprintf(os.Stderr, "warning: could not save run: %v\n", saveErr)
		}
		color.New(color.FgRed).Fprintf(os.Stderr, "\nRun failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "State: %s\n", r.GetState())
		if r.Error != "" {
			fmt.Fprintf(os.Stderr, "Error: %s\n", r.Error)
		}
		return fmt.Errorf("run failed: %w", err)
	}

	// Save successful run
	if savedPath, saveErr := r.Save(); saveErr != nil {
		dim.Fprintf(os.Stderr, "warning: could not save run: %v\n", saveErr)
	} else {
		dim.Fprintf(os.Stderr, "Run saved: %s\n", savedPath)
	}

	color.New(color.FgGreen).Fprintln(os.Stderr, "\nRun completed successfully.")
	fmt.Fprintf(os.Stderr, "Run: %s\n", r.ID)
	fmt.Fprintf(os.Stderr, "State: %s\n", r.GetState())

	// Record history for future estimates
	recordRunHistory(r, p)

	return nil
}

func setupRunLogFile(r *run.Run) (io.Writer, io.Closer) {
	dir, err := run.StoreDir()
	if err != nil {
		return os.Stdout, nil
	}
	logPath := filepath.Join(dir, r.ID+".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return os.Stdout, nil
	}
	r.LogFile = logPath
	return io.MultiWriter(os.Stdout, f), f
}

func recordRunHistory(r *run.Run, p *types.Plan) {
	history, err := cost.NewHistoryStore()
	if err != nil {
		return
	}
	var actualDuration time.Duration
	if !r.StartedAt.IsZero() && !r.FinishedAt.IsZero() {
		actualDuration = r.FinishedAt.Sub(r.StartedAt)
	}
	estCost := 0.0
	if p.Recommendation != nil {
		estCost = p.Recommendation.EstimatedCost.Value
	}
	_ = history.Record(cost.RunHistory{
		RunID:          r.ID,
		TargetID:       r.TargetID,
		WorkloadKind:   string(p.Workload.DetectedKind),
		WorkloadName:   p.Workload.Name,
		Runtime:        string(p.Workload.Runtime),
		ActualDuration: actualDuration,
		EstimatedCost:  estCost,
		ActualCost:     r.Cost.Value,
		Confidence:     string(r.Cost.Confidence),
		CompletedAt:    r.FinishedAt,
		Success:        r.GetState() == types.RunStateCompleted,
	})
}

func adapterForTarget(targetID string) (adapter.TargetAdapter, error) {
	// Check known adapters by ID first
	switch targetID {
	case "local-process":
		return adapter.NewLocalAdapter(), nil
	case "local-docker":
		return adapter.NewDockerAdapter(), nil
	case "lima-vm":
		return cloudvm.NewCloudVMAdapter(
			cloudvm.NewLimaProvider(),
			cloudvm.Config{ProviderID: cloudvm.ProviderLima, SSHUser: "lima"},
		), nil
	case "kubernetes":
		return cloudvm.NewK8sAdapter(""), nil
	case "hetzner-vm":
		return cloudvm.NewCloudVMAdapter(
			cloudvm.NewHetznerProvider(""),
			cloudvm.Config{ProviderID: cloudvm.ProviderHetzner},
		), nil
	case "aws-vm":
		return cloudvm.NewCloudVMAdapter(
			cloudvm.NewAWSProvider(""),
			cloudvm.Config{ProviderID: cloudvm.ProviderAWS, SSHUser: "ubuntu"},
		), nil
	case "gcp-vm":
		return cloudvm.NewCloudVMAdapter(
			cloudvm.NewGCPProvider("", ""),
			cloudvm.Config{ProviderID: cloudvm.ProviderGCP, SSHUser: "dispatcher"},
		), nil
	case "azure-vm":
		return cloudvm.NewCloudVMAdapter(
			cloudvm.NewAzureProvider("dispatcher-rg", ""),
			cloudvm.Config{ProviderID: cloudvm.ProviderAzure, SSHUser: "dispatcher"},
		), nil
	}

	// For unknown IDs, check the target registry for SSH targets
	reg := loadRegistry()
	t, ok := reg.Get(targetID)
	if !ok {
		return nil, fmt.Errorf("no adapter available for target %q", targetID)
	}

	if t.Kind == types.TargetKindSSH {
		cfg := adapter.SSHConfig{Host: "localhost", User: "root", Port: 22}
		if t.SSH != nil {
			if t.SSH.Host != "" {
				cfg.Host = t.SSH.Host
			}
			if t.SSH.User != "" {
				cfg.User = t.SSH.User
			}
			if t.SSH.Port > 0 {
				cfg.Port = t.SSH.Port
			}
			cfg.KeyFile = t.SSH.KeyFile
		}
		return adapter.NewSSHAdapter(cfg), nil
	}

	return nil, fmt.Errorf("no adapter available for target %q (kind %s not yet supported for execution)", targetID, t.Kind)
}
