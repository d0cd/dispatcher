package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/plan"
	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/shard"
	"github.com/d0cd/dispatcher/internal/target"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/d0cd/dispatcher/internal/workload"
)

var runFlags struct {
	target         string
	optimize       string
	maxCost        float64
	timeout        string
	gpu            string
	region         string
	yes            bool
	retryTransient bool
	watchdogTTL    string
	allowSSHFrom   string
}

var runCmd = &cobra.Command{
	Use:   "run [path]",
	Short: "Plan and execute a workload (defaults to current directory)",
	Long:  "Generates a plan for the workload at the given path, then executes it on the recommended target.\n\nIf path is omitted, the current directory is used.\n\nExit codes:\n  0  workload completed successfully\n  1  setup/plan/cleanup failure (no feasible target, validation error, cleanup error, anything before or after execution)\n  2  approval denied (a required policy gate was rejected)\n  3  workload-level failure (non-zero exit, OOM kill, budget exceeded)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRun,
}

func init() {
	runCmd.Flags().StringVar(&runFlags.target, "target", "", "run on a specific target")
	runCmd.Flags().StringVar(&runFlags.optimize, "optimize", "cost", "optimize for: cost, speed")
	runCmd.Flags().Float64Var(&runFlags.maxCost, "max-cost", 0, "maximum estimated cost in USD")
	runCmd.Flags().StringVar(&runFlags.gpu, "gpu", "", "GPU requirement (e.g. 1, a100:1)")
	runCmd.Flags().StringVar(&runFlags.region, "region", "", "cloud region/zone to provision in and tear down from (e.g. eu-west-1, us-central1-a); overrides dispatcher.yaml region")
	runCmd.Flags().StringVar(&runFlags.timeout, "timeout", "", "maximum run duration (e.g. 30m, 2h)")
	runCmd.Flags().BoolVarP(&runFlags.yes, "yes", "y", false, "auto-approve all policy gates")
	runCmd.Flags().BoolVar(&runFlags.retryTransient, "retry-transient", false,
		"retry once on environmental failures (OOM kill, SIGKILL, SIGTERM); does NOT retry workload bugs")
	runCmd.Flags().StringVar(&runFlags.watchdogTTL, "watchdog-ttl", "",
		"cloud VM self-destruct timer if dispatcher dies (e.g. 15m, 2h); default 30m")
	runCmd.Flags().StringVar(&runFlags.allowSSHFrom, "allow-ssh-from", "",
		"restrict cloud VM inbound SSH to this CIDR via a per-run firewall (e.g. 203.0.113.4/32); hetzner-vm and aws-vm")
	rootCmd.AddCommand(runCmd)
}

// parseOptimize maps the --optimize flag value to an OptimizeGoal, rejecting
// typos instead of silently downgrading to cost.
func parseOptimize(s string) (types.OptimizeGoal, error) {
	switch s {
	case "cost":
		return types.OptimizeCost, nil
	case "speed":
		return types.OptimizeSpeed, nil
	default:
		return "", fmt.Errorf("invalid --optimize %q: must be \"cost\" or \"speed\"", s)
	}
}

// perRunFirewallSupported reports whether the target's provider implements the
// per-run SSH firewall (VMOptions.AllowSSHFrom). Only these targets accept
// --allow-ssh-from; the rest reject it rather than silently ignore it.
func perRunFirewallSupported(target string) bool {
	switch target {
	case "hetzner-vm", "aws-vm":
		return true
	default:
		return false
	}
}

func runRun(cmd *cobra.Command, args []string) error {
	raw := "."
	if len(args) > 0 {
		raw = args[0]
	}
	path, err := filepath.Abs(raw)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", raw, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot read %s (does it exist?): %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path must be a directory; %s is a file", path)
	}

	optimizeFor, err := parseOptimize(runFlags.optimize)
	if err != nil {
		return err
	}

	if runFlags.allowSSHFrom != "" {
		if _, _, err := net.ParseCIDR(runFlags.allowSSHFrom); err != nil {
			return fmt.Errorf("invalid --allow-ssh-from %q: must be a CIDR like 203.0.113.4/32", runFlags.allowSSHFrom)
		}
	}

	var maxDuration time.Duration
	if runFlags.timeout != "" {
		d, err := time.ParseDuration(runFlags.timeout)
		if err != nil {
			return fmt.Errorf("invalid timeout %q: %w", runFlags.timeout, err)
		}
		maxDuration = d
	}

	var watchdogTTL time.Duration
	if runFlags.watchdogTTL != "" {
		d, err := time.ParseDuration(runFlags.watchdogTTL)
		if err != nil {
			return fmt.Errorf("invalid --watchdog-ttl %q: %w", runFlags.watchdogTTL, err)
		}
		watchdogTTL = d
	}

	constraints := types.PlanConstraints{
		TargetScope:            "workspace-defaults",
		OptimizeFor:            optimizeFor,
		MaxEstimatedCostUSD:    runFlags.maxCost,
		MaxDuration:            maxDuration,
		RequireGPU:             runFlags.gpu,
		TargetName:             runFlags.target,
		Region:                 runFlags.region,
		WatchdogTTL:            watchdogTTL,
		RetryTransientFailures: runFlags.retryTransient,
		AllowSSHFrom:           runFlags.allowSSHFrom,
	}

	// Generate plan
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	bold.Fprintln(os.Stderr, "Planning...")
	catalog := loadLiveCatalogScoped(os.Stderr, constraints.TargetName, constraints.Region)
	p, err := plan.Build(path, constraints, catalog)
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

	// Reject --allow-ssh-from for targets whose provider doesn't implement a
	// per-run firewall, failing before creating a run/VM rather than deep inside
	// provisioning (or silently ignoring the requested restriction).
	if runFlags.allowSSHFrom != "" && !perRunFirewallSupported(p.Recommendation.Target) {
		return fmt.Errorf("--allow-ssh-from is not supported on %s (only hetzner-vm and aws-vm implement a per-run SSH firewall) — restrict SSH at the account/VPC level instead", p.Recommendation.Target)
	}

	// Show summary
	fmt.Fprintf(os.Stderr, "Using plan:        %s\n", p.Metadata.ID)
	fmt.Fprintf(os.Stderr, "Target:            %s\n", p.Recommendation.Target)
	fmt.Fprintf(os.Stderr, "Estimated cost:    %s %s\n", formatCost(p.Recommendation.EstimatedCost.Value), p.Recommendation.EstimatedCost.Currency)

	if len(p.RequiredApprovals) > 0 {
		color.New(color.FgYellow).Fprintln(os.Stderr, "Approvals required:")
		for _, a := range p.RequiredApprovals {
			fmt.Fprintf(os.Stderr, "  - %s: %s\n", a.Name, a.Reason)
		}
		fmt.Fprintln(os.Stderr)
	}

	// Sharded fan-out: run the workload across N shards, each a full run.
	if p.Workload.Shard.Enabled() {
		// A sharded run auto-approves each shard, so a plan needing approval
		// must be approved once, up front, via --yes — never silently bypassed.
		if len(p.RequiredApprovals) > 0 && !runFlags.yes {
			return fmt.Errorf("this plan requires approval; sharded runs auto-approve each shard — pass --yes to approve the whole fan-out")
		}
		shardCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if maxDuration > 0 {
			var cancel context.CancelFunc
			shardCtx, cancel = context.WithTimeout(shardCtx, maxDuration)
			defer cancel()
		}
		outcomes := newShardOutcomes()
		runErr := runSharded(shardCtx, p, func(ctx context.Context, a shard.Assignment) error {
			r, err := runOneShard(ctx, p, a)
			outcomes.record(a.Index, r)
			return err
		})
		// Aggregate outputs regardless of the run outcome — a partial fan-out
		// still collected whatever its shards produced.
		if dirs := outcomes.artifactDirs(); len(dirs) > 0 {
			runsDir, _ := run.StoreDir()
			destRoot := filepath.Join(runsDir, p.Metadata.ID+"-shards")
			if n, aggErr := aggregateShardArtifacts(destRoot, dirs); aggErr != nil {
				dim.Fprintf(os.Stderr, "warning: shard output aggregation incomplete: %v\n", aggErr)
			} else if n > 0 {
				fmt.Fprintf(os.Stderr, "Aggregated outputs from %d shards under %s\n", n, destRoot)
			}
		}
		return runErr
	}

	// Select adapter — confidential runs take an attesting backend; everything
	// else resolves by target ID.
	a, err := adapterForPlan(cmd.Context(), p)
	if err != nil {
		return err
	}

	// Preflight external inputs before provisioning: a bounded Range read of each
	// DISPATCHER_INPUT* URI catches a 403/404 source failure here — before a paid
	// VM is created — instead of after staging fails on the box. A definitive
	// source error aborts; a transport error also aborts (don't pay to provision
	// against an unreachable source) but is labeled as possibly transient.
	env, _ := workload.LoadDotEnv(p.Workload.Source.Path) // best-effort; refs also come from spec env
	if env == nil {
		env = map[string]string{}
	}
	for k, v := range p.Workload.Env {
		env[k] = v // spec-level env wins over .env
	}
	if refs := workload.InputRefs(env); len(refs) > 0 {
		client := &http.Client{Timeout: 20 * time.Second}
		if err := workload.PreflightInputs(cmd.Context(), refs, client); err != nil {
			return fmt.Errorf("input preflight failed: %w", err)
		}
		dim.Fprintf(os.Stderr, "Preflighted %d external input(s)\n", len(refs))
	}

	// Create and execute run
	r := run.NewRun(p)
	executor := run.NewExecutor(a)
	// Always install an approver so the executor never falls into its
	// fail-closed branch on the happy path. `--yes` installs an auto-
	// approver that records "yes-flag" in the audit trail (distinct from
	// "interactive" approvals).
	if runFlags.yes {
		executor.SetApprovalFunc(yesApproval)
	} else {
		executor.SetApprovalFunc(terminalApproval)
	}

	bold.Fprintf(os.Stderr, "\nRun: %s\n", r.ID)
	fmt.Fprintln(os.Stderr, "Status: running")
	fmt.Fprintln(os.Stderr)

	// Ctrl-C / SIGTERM cancels the run context so in-flight provisioning unwinds
	// and the adapter's cleanup (which uses a fresh context) tears down any
	// half-created VM, instead of the process dying and leaking it. The deferred
	// stop() restores Go's default handler only when runRun returns, so a second
	// signal during cleanup is absorbed rather than interrupting teardown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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

	// Heartbeat: print elapsed time every 30s so the user knows we're alive.
	// Stop when execute returns.
	stopHeartbeat := make(chan struct{})
	go runHeartbeat(r, stopHeartbeat)

	err = executor.Execute(ctx, r, logWriter)
	close(stopHeartbeat)
	if err != nil {
		// Save run state even on failure
		if _, saveErr := r.Save(); saveErr != nil {
			dim.Fprintf(os.Stderr, "warning: could not save run: %v\n", saveErr)
		}
		// Record failed runs in history too, so `dispatcher bill` and
		// historical-confidence tracking don't undercount. Without this,
		// every failed cloud run silently dropped its spend.
		recordRunHistory(r, p)
		color.New(color.FgRed).Fprintf(os.Stderr, "\nRun failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "State: %s\n", r.GetState())
		if r.Error != "" {
			fmt.Fprintf(os.Stderr, "Error: %s\n", r.Error)
		}
		switch r.GetState() {
		case types.RunStateApprovalDenied:
			return &ExitError{Code: 2, Err: err, AlreadyPrinted: true}
		case types.RunStateExecutionFailed, types.RunStateBudgetExceeded:
			return &ExitError{Code: 3, Err: err, AlreadyPrinted: true}
		}
		return &ExitError{Code: 1, Err: err, AlreadyPrinted: true}
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

	recordRunHistory(r, p)
	return nil
}

// runHeartbeat prints elapsed time + current run state every 30s until
// the stop channel closes. Output goes to stderr so it doesn't pollute logs.
func runHeartbeat(r *run.Run, stop <-chan struct{}) {
	dim := color.New(color.Faint)
	start := time.Now()
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			elapsed := time.Since(start).Round(time.Second)
			dim.Fprintf(os.Stderr, "  ... %s elapsed (%s)\n", elapsed, r.GetState())
		}
	}
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
	state := r.GetState()
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
		Success:        state == types.RunStateCompleted,
		FinalState:     string(state),
		FailureMessage: r.Failure.Message,
	})
}

// adapterForTargetFn is the seam status's primary reconnect path (runStatusByID)
// uses to resolve an adapter; tests override it to inject a fake durable adapter.
var adapterForTargetFn = adapterForTarget

// adapterForPlan selects the execution adapter for a plan: an attesting
// confidential backend when the workload requests confidential compute, else
// the plain target adapter. Every execution path (single run AND each shard)
// must go through this — resolving a confidential plan via adapterForTarget
// would silently drop attestation.
func adapterForPlan(ctx context.Context, p *types.Plan) (adapter.TargetAdapter, error) {
	// Fail closed on a measured-profile / target mismatch. Feasibility already
	// prevents the plan from recommending a cross-cloud target, but a persisted
	// or hand-forced plan must never silently fall through to a provider's
	// unmeasured default backend.
	if c := p.Workload.Requirements.Confidential; c.Required && c.Attestation != "off" && p.Recommendation != nil {
		if req := target.RequiredTargetForProfile(c.Profile); req != "" && p.Recommendation.Target != req {
			return nil, fmt.Errorf("confidential.profile: %s requires target %s, but the plan selected %s", c.Profile, req, p.Recommendation.Target)
		}
	}
	switch {
	case usesConfidentialSpace(p):
		return newConfidentialSpaceAdapter(ctx)
	case usesAzureSNP(p):
		return newAzureSNPConfidentialAdapter(ctx)
	case usesAWSNitro(p):
		return newNitroConfidentialAdapter(ctx)
	default:
		// A confidential run with attestation on MUST resolve to an attesting
		// backend. If none of the predicates matched (e.g. an empty profile on a
		// target that isn't one of the three cloud confidential backends), fail
		// closed rather than silently using a plain, non-attesting adapter.
		// `attestation: off` is the escape hatch and still uses the plain path.
		if c := p.Workload.Requirements.Confidential; c.Required && c.Attestation != "off" && p.Recommendation != nil {
			switch p.Recommendation.Target {
			case "aws-vm":
				return nil, fmt.Errorf("AWS attestation requires confidential.profile: nitro; the standard SEV-SNP path cannot release secrets because its post-boot agent is not measured")
			case "azure-vm":
				return nil, fmt.Errorf("confidential attestation on azure-vm requires confidential.profile: azure-snp; the standard MAA path cannot release secrets because its post-boot agent is not measured")
			default:
				return nil, fmt.Errorf("confidential attestation required but target %q has no attesting backend", p.Recommendation.Target)
			}
		}
		return adapterForTarget(p.Recommendation.Target)
	}
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
	case "oci-vm":
		// SSHUser is image-dependent (Ubuntu images use "ubuntu", Oracle Linux
		// "opc"); the operator supplies a matching DISPATCHER_OCI_IMAGE_ID.
		return cloudvm.NewCloudVMAdapter(
			cloudvm.NewOCIProvider(os.Getenv("DISPATCHER_OCI_REGION")),
			cloudvm.Config{ProviderID: cloudvm.ProviderOCI, SSHUser: "ubuntu"},
		), nil
	case "gcp-confidential-space":
		// Reconnect/status/cleanup only drive VM lifecycle + stored state, so the
		// verifier keys and image builder (needed only by Execute) are nil here.
		return cloudvm.NewConfidentialSpaceAdapter(
			cloudvm.NewGCPProvider(gcpProject(), ""),
			nil, nil,
			cloudvm.Config{ProviderID: cloudvm.ProviderGCP},
		), nil
	case "firecracker-vm":
		return cloudvm.NewCloudVMAdapter(
			cloudvm.NewFirecrackerProvider(),
			cloudvm.Config{ProviderID: cloudvm.ProviderFirecracker, SSHUser: "root"},
		), nil
	}

	// For unknown IDs, check the target registry for SSH targets
	reg := loadRegistry()
	t, ok := reg.Get(targetID)
	if !ok {
		return nil, fmt.Errorf("no adapter available for target %q", targetID)
	}

	if t.Kind == types.TargetKindSSH {
		if t.SSH == nil || t.SSH.Host == "" {
			return nil, fmt.Errorf("ssh target %q has no host configured; set ssh.host in its target YAML or recreate with `dispatcher targets add %s --host <addr>`", targetID, targetID)
		}
		cfg := adapter.SSHConfig{Host: t.SSH.Host, User: "root", Port: 22}
		if t.SSH.User != "" {
			cfg.User = t.SSH.User
		}
		if t.SSH.Port > 0 {
			cfg.Port = t.SSH.Port
		}
		cfg.KeyFile = t.SSH.KeyFile
		return adapter.NewSSHAdapter(cfg), nil
	}

	return nil, fmt.Errorf("no adapter available for target %q (kind %s not yet supported for execution)", targetID, t.Kind)
}
