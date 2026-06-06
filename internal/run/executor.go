package run

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/approval"
	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/types"
)

// ApprovalFunc is called when a plan requires approvals.
// It receives the list of required approvals and returns nil if approved,
// or an error (typically ErrApprovalDenied) if denied.
type ApprovalFunc func(approvals []types.PolicyRequirement) error

// ErrApprovalDenied is returned when the user denies a required approval.
var ErrApprovalDenied = fmt.Errorf("approval denied by user")

// Executor orchestrates run lifecycle using a target adapter.
type Executor struct {
	adapter    adapter.TargetAdapter
	approvalFn ApprovalFunc
}

// NewExecutor creates an executor for the given adapter.
func NewExecutor(a adapter.TargetAdapter) *Executor {
	return &Executor{adapter: a}
}

// SetApprovalFunc configures the function called for interactive approvals.
// If nil, approvals are auto-granted (default for backward compat).
func (e *Executor) SetApprovalFunc(fn ApprovalFunc) {
	e.approvalFn = fn
}

// Execute runs the full lifecycle with guaranteed cleanup and panic recovery.
func (e *Executor) Execute(ctx context.Context, r *Run, logWriter io.Writer) error {
	// Panic recovery: catch panics, persist error state, attempt cleanup.
	defer func() {
		if rec := recover(); rec != nil {
			r.SetError(types.RunStateExecutionFailed,
				fmt.Errorf("executor panic: %v", rec))
			r.Save()
			e.attemptCleanup(context.Background(), r)
		}
	}()

	// Planning/validation
	if err := r.Transition(types.RunStatePlanning); err != nil {
		return err
	}

	validation, err := e.adapter.Validate(ctx, r.Plan.Workload)
	if err != nil {
		r.SetError(types.RunStatePlanInvalid, err)
		return fmt.Errorf("validation failed: %w", err)
	}
	if !validation.IsValid() {
		r.SetError(types.RunStatePlanInvalid, fmt.Errorf("plan validation failed"))
		return fmt.Errorf("plan validation failed")
	}

	if err := r.Transition(types.RunStateValidated); err != nil {
		return err
	}

	// Check approvals
	if len(r.Plan.RequiredApprovals) > 0 {
		if err := r.Transition(types.RunStateAwaitingApproval); err != nil {
			return err
		}

		preApproved := false
		if existing, err := approval.Load(r.ID); err == nil {
			switch existing.Decision {
			case approval.DecisionApproved:
				preApproved = true
				dlog.L().Info("approval.preapproved", "run", r.ID, "decider", existing.Decider)
			case approval.DecisionDenied:
				r.SetError(types.RunStateApprovalDenied, ErrApprovalDenied)
				return fmt.Errorf("approval previously denied")
			}
		}

		if !preApproved {
			_, _, _ = approval.RequestPending(r.ID, r.Plan.RequiredApprovals)
			if e.approvalFn != nil {
				if err := e.approvalFn(r.Plan.RequiredApprovals); err != nil {
					_, _ = approval.Resolve(r.ID, approval.DecisionDenied, "interactive")
					r.SetError(types.RunStateApprovalDenied, err)
					return fmt.Errorf("approval denied: %w", err)
				}
				_, _ = approval.Resolve(r.ID, approval.DecisionApproved, "interactive")
			}
			// If no approvalFn set, the pending record sits for `dispatcher approve` to resolve.
		}
	}

	// Prepare
	if err := r.Transition(types.RunStatePreparing); err != nil {
		return err
	}

	if err := e.adapter.Prepare(ctx, r.Plan); err != nil {
		r.SetError(types.RunStatePackageFailed, err)
		return fmt.Errorf("preparation failed: %w", err)
	}

	// Execute
	if err := r.Transition(types.RunStateRunning); err != nil {
		return err
	}

	handle, err := e.adapter.Execute(ctx, r.Plan)
	if err != nil {
		r.SetError(types.RunStateExecutionFailed, err)
		return fmt.Errorf("execution failed: %w", err)
	}
	r.Handle = handle

	// Persist handle immediately — if CLI crashes after this point,
	// we can reconnect using the persisted state.
	if err := r.PersistHandle(); err != nil {
		if logWriter != nil {
			fmt.Fprintf(logWriter, "[dispatcher] warning: could not persist handle: %v\n", err)
		}
	}

	// Determine lifecycle
	r.Lifecycle = LifecycleForWorkload(r.Plan.Workload.DetectedKind)
	r.Save()

	// For long-running workloads on durable adapters, detach and return.
	if r.Lifecycle == LifecycleLongRunning {
		if _, ok := e.adapter.(adapter.DurableAdapter); ok {
			return e.startLongRunning(ctx, r, logWriter)
		}
	}

	// For ephemeral workloads, run the full lifecycle with guaranteed cleanup.
	return e.executeEphemeral(ctx, r, handle, logWriter)
}

// executeEphemeral runs the post-execution lifecycle with guaranteed cleanup.
func (e *Executor) executeEphemeral(ctx context.Context, r *Run,
	handle *adapter.RunHandle, logWriter io.Writer) error {

	// GUARANTEED CLEANUP: fires even if Status/Artifacts/Cost fail.
	// Uses a fresh context so cleanup works even if the original was canceled.
	cleanupDone := false
	defer func() {
		if !cleanupDone {
			e.attemptCleanup(context.Background(), r)
			r.Save()
		}
	}()

	stopSampler := e.startCostSampler(ctx, r, handle, logWriter)
	defer stopSampler()

	// Stream logs (non-fatal)
	if logWriter != nil {
		if err := e.adapter.Logs(ctx, handle, logWriter); err != nil {
			fmt.Fprintf(logWriter, "[dispatcher] warning: log streaming error: %v\n", err)
		}
	}

	// Check final status
	state, err := e.adapter.Status(ctx, handle)
	if err != nil {
		r.SetError(types.RunStateExecutionFailed, err)
		return fmt.Errorf("status check failed: %w", err)
	}
	if state == types.RunStateExecutionFailed {
		r.SetError(types.RunStateExecutionFailed, fmt.Errorf("workload execution failed"))
		return fmt.Errorf("workload execution failed")
	}

	// Collect artifacts (failure is non-fatal for cleanup)
	if err := r.Transition(types.RunStateCollectingArtifacts); err == nil {
		if artifacts, err := e.adapter.Artifacts(ctx, handle); err == nil {
			r.Artifacts = artifacts
		} else if logWriter != nil {
			fmt.Fprintf(logWriter, "[dispatcher] warning: artifact collection failed: %v\n", err)
		}
	}

	// Reconcile cost
	if err := r.Transition(types.RunStateReconcilingCost); err == nil {
		r.FinalizeCost()
	}

	// Explicit cleanup path (prevents the deferred cleanup from firing twice)
	e.attemptCleanup(context.Background(), r)
	r.Save()
	cleanupDone = true

	if r.GetState() == types.RunStateCleanupFailed {
		return fmt.Errorf("cleanup failed")
	}

	return nil
}

// startLongRunning sets up a long-running workload that survives CLI exit.
func (e *Executor) startLongRunning(ctx context.Context, r *Run, logWriter io.Writer) error {
	durable, ok := e.adapter.(adapter.DurableAdapter)
	if !ok {
		return fmt.Errorf("long-running workloads require a durable adapter")
	}

	// Extend watchdog for initial TTL
	r.WatchdogTTL = 30 * time.Minute
	if _, err := durable.ExtendWatchdog(ctx, r.Handle, r.WatchdogTTL); err != nil {
		if logWriter != nil {
			fmt.Fprintf(logWriter, "[dispatcher] warning: initial watchdog extension failed: %v\n", err)
		}
	}
	r.LastHeartbeat = time.Now().UTC()
	r.Save()

	if logWriter != nil {
		fmt.Fprintf(logWriter, "[dispatcher] Workload running on %s.\n", r.TargetID)
		fmt.Fprintf(logWriter, "[dispatcher] Use 'dispatcher status %s' to check status.\n", r.ID)
		fmt.Fprintf(logWriter, "[dispatcher] Use 'dispatcher logs %s' to stream logs.\n", r.ID)
		fmt.Fprintf(logWriter, "[dispatcher] Use 'dispatcher stop %s' to tear down.\n", r.ID)
	}

	return nil
}

// attemptCleanup tries cleanup with retries. Never panics.
// CostSampleInterval is exposed so tests can shorten it.
var CostSampleInterval = 5 * time.Second

// startCostSampler periodically computes the run's live cost and terminates
// the workload if PlanConstraints.MaxEstimatedCostUSD is breached. Returns a
// stop function that cancels the sampler; callers must defer it.
func (e *Executor) startCostSampler(ctx context.Context, r *Run, handle *adapter.RunHandle, logWriter io.Writer) func() {
	budget := r.Plan.Constraints.MaxEstimatedCostUSD
	if budget <= 0 {
		return func() {}
	}

	sampleCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(CostSampleInterval)
		defer ticker.Stop()

		for {
			select {
			case <-sampleCtx.Done():
				return
			case <-ticker.C:
				live := r.ComputeLiveCost()
				if live.Value <= budget {
					continue
				}
				if logWriter != nil {
					fmt.Fprintf(logWriter, "[dispatcher] budget exceeded: $%.2f > $%.2f — terminating\n",
						live.Value, budget)
				}
				dlog.L().Warn("budget.exceeded", "run", r.ID, "actual", live.Value, "budget", budget)
				if err := r.Transition(types.RunStateBudgetExceeded); err == nil {
					r.Cost = live
					_ = e.adapter.Terminate(context.Background(), handle)
				}
				return
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

func (e *Executor) attemptCleanup(ctx context.Context, r *Run) {
	if r.Handle == nil {
		return
	}
	state := r.GetState()
	if state == types.RunStateCompleted {
		return
	}

	const maxRetries = 3
	for i := 0; i < maxRetries; i++ {
		// Try to transition to CleaningUp. If the state machine rejects it,
		// we still attempt the cleanup call.
		_ = r.Transition(types.RunStateCleaningUp)

		result, err := e.adapter.Cleanup(ctx, r.Handle)
		if err == nil && result != nil && result.Success {
			_ = r.Transition(types.RunStateCompleted)
			return
		}

		if i < maxRetries-1 {
			time.Sleep(time.Duration(1<<uint(i)) * time.Second)
		}
	}
	r.SetError(types.RunStateCleanupFailed, fmt.Errorf("cleanup failed after %d retries", maxRetries))
}

