package run

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/approval"
	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/types"
)

// ApprovalFunc / ErrApprovalDenied alias the approval package for callers
// that key off the run package's symbols.
type ApprovalFunc = approval.ApprovalFunc

var ErrApprovalDenied = approval.ErrDenied

type Executor struct {
	adapter    adapter.TargetAdapter
	approvalFn ApprovalFunc
}

func NewExecutor(a adapter.TargetAdapter) *Executor {
	return &Executor{adapter: a}
}

// SetApprovalFunc installs an in-process approver. Nil means the executor
// only resolves via an external `dispatcher approve <id>` socket.
func (e *Executor) SetApprovalFunc(fn ApprovalFunc) {
	e.approvalFn = fn
}

// saveRun persists the run, logging a warning if the write fails. Used at
// call sites that cannot propagate the error (deferred cleanup, panic
// recovery, post-detach heartbeat) so a failed persist is surfaced rather
// than silently dropped.
func saveRun(r *Run) {
	if _, err := r.Save(); err != nil {
		dlog.L().Warn("run.save.failed", "run", r.ID, "err", err.Error())
	}
}

// Execute runs the full lifecycle with guaranteed cleanup and panic recovery.
func (e *Executor) Execute(ctx context.Context, r *Run, logWriter io.Writer) error {
	defer func() {
		if rec := recover(); rec != nil {
			r.SetError(types.RunStateExecutionFailed,
				fmt.Errorf("executor panic: %v", rec))
			saveRun(r)
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

	if len(r.Plan.RequiredApprovals) > 0 {
		if err := r.Transition(types.RunStateAwaitingApproval); err != nil {
			return err
		}
		gate, err := approval.NewGate(r.ID, r.Plan.RequiredApprovals)
		if err != nil {
			r.SetError(types.RunStateApprovalDenied, err)
			return fmt.Errorf("open approval gate: %w", err)
		}
		defer gate.Close()

		if e.approvalFn == nil {
			dlog.L().Info("approval.awaiting_external", "run", r.ID)
		}

		rec, err := gate.Wait(ctx, e.approvalFn)
		r.Approval = &rec // stamp record on both approve and deny paths
		if err != nil {
			r.SetError(types.RunStateApprovalDenied, err)
			return fmt.Errorf("approval denied: %w", err)
		}
		dlog.L().Info("approval.granted", "run", r.ID, "decider", rec.Decider)
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
	// Stamp the run id onto the handle so adapters that need it (e.g.
	// CloudVMAdapter.Artifacts placing files under runs/<run-id>/) can
	// reach it without parsing handle.ID — which is provider-specific.
	handle.RunID = r.ID
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
	saveRun(r)

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
			saveRun(r)
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

	// Wait for the workload to reach a terminal state. Blocking-Status adapters
	// (local/docker) return terminal on the first call; poll-based durable
	// adapters (cloud VM, k8s) report Running until the workload finishes, so
	// we must poll rather than tear the run down on the first reading.
	state, err := e.waitForTerminal(ctx, handle, r.Plan.Constraints.MaxDuration)

	// Collect artifacts BEFORE we transition to a terminal state — even on
	// failure. Crash dumps and partial outputs are usually exactly what the
	// user wants; losing them to cleanup defeats the point. Failure is
	// logged but non-fatal so cleanup still runs.
	if tErr := r.Transition(types.RunStateCollectingArtifacts); tErr == nil {
		if artifacts, aErr := e.adapter.Artifacts(ctx, handle); aErr == nil {
			r.Artifacts = artifacts
		} else if logWriter != nil {
			fmt.Fprintf(logWriter, "[dispatcher] warning: artifact collection failed: %v\n", aErr)
		}
	}

	// Capture failure details from the adapter if it supports rich reporting.
	// Always do this — we want the data on the run record for diagnose, even
	// if retry is disabled. classification gates the optional retry below.
	if err != nil || state == types.RunStateExecutionFailed {
		if fr, ok := e.adapter.(adapter.FailureReporter); ok {
			r.Failure = fr.FailureDetails(handle)
		}
	}

	if err != nil {
		r.SetError(types.RunStateExecutionFailed, err)
		return fmt.Errorf("status check failed: %w", err)
	}
	if state == types.RunStateExecutionFailed {
		kind := adapter.ClassifyFailure(r.Failure)
		if logWriter != nil {
			fmt.Fprintf(logWriter, "[dispatcher] failure classified as %s: %s\n", kind, r.Failure.Message)
		}
		// Opt-in retry: only when the user explicitly asked AND the failure
		// looks transient AND we haven't already retried.
		retrySucceeded := false
		if r.Plan.Constraints.RetryTransientFailures &&
			kind == adapter.FailureTransient &&
			r.RetryCount == 0 {
			if logWriter != nil {
				fmt.Fprintf(logWriter, "[dispatcher] retrying transient failure once\n")
			}
			r.RetryCount++
			r.Failure = adapter.FailureDetails{}
			// Tear down the failed attempt's resources before re-provisioning.
			// The retry overwrites r.Handle, so without this the first
			// attempt's VM/Job would be orphaned and keep billing until the
			// watchdog TTL or `dispatcher gc` reclaims it.
			if _, cErr := e.adapter.Cleanup(context.Background(), handle); cErr != nil {
				dlog.L().Warn("retry.cleanup.failed", "run", r.ID, "err", cErr.Error())
			}
			// A retry is a fresh run from the adapter's perspective. The
			// previous handle is dead; ask the adapter for a new one. Cloud
			// VM re-provisioning lives behind adapter.Execute, so this path
			// "just works" wherever Execute is itself safe to call twice
			// (local, docker today; cloud-vm would re-provision a new VM).
			if retryHandle, retryErr := e.adapter.Execute(ctx, r.Plan); retryErr == nil {
				retryHandle.RunID = r.ID
				handle = retryHandle
				r.Handle = retryHandle
				_ = r.PersistHandle()
				// Wait for the new run. We deliberately don't re-stream logs
				// here to keep the retry path narrow — the original log
				// writer is closed.
				state, err = e.waitForTerminal(ctx, handle, r.Plan.Constraints.MaxDuration)
				if err == nil && state != types.RunStateExecutionFailed {
					retrySucceeded = true
				} else if fr, ok := e.adapter.(adapter.FailureReporter); ok {
					// Retry also failed — capture details for the final
					// run record. ClassifyFailure on the post-retry detail
					// will say "permanent" by definition (we already gave
					// it one shot).
					r.Failure = fr.FailureDetails(handle)
				}
			} else if logWriter != nil {
				fmt.Fprintf(logWriter, "[dispatcher] retry execute failed: %v\n", retryErr)
			}
		}
		if !retrySucceeded {
			r.SetError(types.RunStateExecutionFailed, fmt.Errorf("workload execution failed"))
			return fmt.Errorf("workload execution failed")
		}
	}

	// Reconcile cost
	if err := r.Transition(types.RunStateReconcilingCost); err == nil {
		r.FinalizeCost()
	}

	// Explicit cleanup path (prevents the deferred cleanup from firing twice)
	e.attemptCleanup(context.Background(), r)
	saveRun(r)
	cleanupDone = true

	if r.GetState() == types.RunStateCleanupFailed {
		return fmt.Errorf("cleanup failed")
	}

	return nil
}

// waitForTerminal polls the adapter's Status until it returns a terminal state,
// the context is canceled, or maxDuration elapses. Blocking-Status adapters
// (local/docker) return terminal on the first call so the loop exits at once;
// poll-based durable adapters (cloud VM, k8s) return RunStateRunning until the
// workload finishes. On a maxDuration timeout the workload is terminated and
// reported failed; the watchdog is only a backstop for a crashed CLI.
func (e *Executor) waitForTerminal(ctx context.Context, handle *adapter.RunHandle, maxDuration time.Duration) (types.RunState, error) {
	var deadline <-chan time.Time
	if maxDuration > 0 {
		timer := time.NewTimer(maxDuration)
		defer timer.Stop()
		deadline = timer.C
	}

	for {
		state, err := e.adapter.Status(ctx, handle)
		if err != nil {
			return state, err
		}
		if state != types.RunStateRunning {
			return state, nil
		}

		select {
		case <-ctx.Done():
			return state, ctx.Err()
		case <-deadline:
			if termErr := e.adapter.Terminate(context.Background(), handle); termErr != nil {
				dlog.L().Error("maxduration.terminate.failed", "handle", handle.ID, "err", termErr.Error())
			}
			return types.RunStateExecutionFailed,
				fmt.Errorf("workload exceeded max duration %s", maxDuration)
		case <-time.After(time.Duration(statusPollInterval.Load())):
		}
	}
}

// startLongRunning sets up a long-running workload that survives CLI exit.
func (e *Executor) startLongRunning(ctx context.Context, r *Run, logWriter io.Writer) error {
	durable, ok := e.adapter.(adapter.DurableAdapter)
	if !ok {
		return fmt.Errorf("long-running workloads require a durable adapter")
	}

	// Extend watchdog for the initial TTL (configured, or the default).
	if _, err := durable.ExtendWatchdog(ctx, r.Handle, r.effectiveWatchdogTTL()); err != nil {
		if logWriter != nil {
			fmt.Fprintf(logWriter, "[dispatcher] warning: initial watchdog extension failed: %v\n", err)
		}
	}
	r.LastHeartbeat = time.Now().UTC()
	saveRun(r)

	if logWriter != nil {
		fmt.Fprintf(logWriter, "[dispatcher] Workload running on %s.\n", r.TargetID)
		fmt.Fprintf(logWriter, "[dispatcher] Use 'dispatcher status %s' to check status.\n", r.ID)
		fmt.Fprintf(logWriter, "[dispatcher] Use 'dispatcher logs %s' to stream logs.\n", r.ID)
		fmt.Fprintf(logWriter, "[dispatcher] Use 'dispatcher stop %s' to tear down.\n", r.ID)
	}

	return nil
}

// costSampleInterval is the cost-sampling period. Accessed atomically because
// tests temporarily shorten it (via SetCostSampleInterval); the sampler
// goroutine reads it while the test goroutine writes. Stored as nanoseconds
// to fit atomic.Int64.
var costSampleInterval atomic.Int64

// statusPollInterval is how often executeEphemeral re-checks a poll-based
// adapter's Status while a workload is still running. Blocking-Status adapters
// (local/docker) return terminal on the first call and never observe it.
// Test-adjustable via SetStatusPollInterval.
var statusPollInterval atomic.Int64

func init() {
	costSampleInterval.Store(int64(5 * time.Second))
	statusPollInterval.Store(int64(3 * time.Second))
}

// SetStatusPollInterval changes the Status poll period. Test-only; returns the
// previous value so the caller can restore it.
func SetStatusPollInterval(d time.Duration) time.Duration {
	return time.Duration(statusPollInterval.Swap(int64(d)))
}

// SetCostSampleInterval changes the cost-sampling period. Test-only; returns
// the previous value so the caller can restore it.
func SetCostSampleInterval(d time.Duration) time.Duration {
	return time.Duration(costSampleInterval.Swap(int64(d)))
}

// CostSampleInterval returns the current sampling period.
func CostSampleInterval() time.Duration {
	return time.Duration(costSampleInterval.Load())
}

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
		// Adaptive sampling: start at the configured interval (5s default),
		// but tighten as we approach the budget. At >80% of budget we sample
		// every 500ms so the trip fires within ~500ms of the threshold,
		// keeping cost overshoot in the cents not the dollars.
		base := CostSampleInterval()
		ticker := time.NewTicker(base)
		defer ticker.Stop()

		for {
			select {
			case <-sampleCtx.Done():
				return
			case <-ticker.C:
				live := r.ComputeLiveCost()
				if live.Value <= budget {
					adjustSamplerRate(ticker, live.Value, budget, base)
					continue
				}
				overshoot := live.Value - budget
				// Claim the run for termination first. The BudgetExceeded
				// transition is legal only from Running; if it fails the
				// workload already finished on its own in this tick window, so
				// there is nothing to terminate. Log the skip rather than
				// emitting a "terminating" message for a kill that never happens.
				if err := r.Transition(types.RunStateBudgetExceeded); err != nil {
					dlog.L().Info("budget.enforce.skipped",
						"run", r.ID,
						"reason", err.Error(),
						"actual_usd", live.Value,
						"budget_usd", budget)
					return
				}
				r.setCost(live)
				if logWriter != nil {
					fmt.Fprintf(logWriter, "[dispatcher] budget exceeded: $%.4f > $%.2f (overshoot $%.4f) — terminating\n",
						live.Value, budget, overshoot)
				}
				dlog.L().Warn("budget.exceeded",
					"run", r.ID,
					"actual_usd", live.Value,
					"budget_usd", budget,
					"overshoot_usd", overshoot,
					"confidence", string(live.Confidence))
				if termErr := e.adapter.Terminate(context.Background(), handle); termErr != nil {
					dlog.L().Error("budget.terminate.failed",
						"run", r.ID, "err", termErr.Error())
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

// adjustSamplerRate tightens the sampling interval as the live cost
// approaches the budget. Three tiers:
//   - <50%: baseline (e.g. 5s)
//   - 50-80%: half-baseline
//   - >80%: 500ms (cap)
//
// Re-tickering on each call would churn; instead we only Reset when the
// current rate is out of sync with the desired tier.
func adjustSamplerRate(ticker *time.Ticker, live, budget float64, base time.Duration) {
	if budget <= 0 {
		return
	}
	ratio := live / budget
	var want time.Duration
	switch {
	case ratio >= 0.8:
		want = 500 * time.Millisecond
	case ratio >= 0.5:
		want = base / 2
	default:
		want = base
	}
	// Floor so we don't sample faster than 100ms regardless of base.
	if want < 100*time.Millisecond {
		want = 100 * time.Millisecond
	}
	ticker.Reset(want)
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
