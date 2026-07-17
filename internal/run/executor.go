package run

import (
	"context"
	"fmt"
	"io"
	"sync"
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

// setFailure records failure details under the run lock — the cost sampler
// goroutine reads r.Failure via ToRecord under RLock, so the write must be guarded
// too, or it is a data race.
func (r *Run) setFailure(fd adapter.FailureDetails) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Failure = fd
}

// setCleanupError records a teardown failure independently of State (which may
// already be terminal), under the lock the sampler's ToRecord reads.
func (r *Run) setCleanupError(msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.CleanupError = msg
}

// beginRetry increments the retry counter and clears the prior failure under the
// lock (same reason as setFailure).
func (r *Run) beginRetry() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.RetryCount++
	r.Failure = adapter.FailureDetails{}
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

// collectArtifacts transitions the run to CollectingArtifacts and retrieves the
// declared outputs from the given handle (crash dumps on failure, real outputs
// on success), retrying a transient transport failure with bounded backoff.
// Returns true only when the outputs were retrieved. Called exactly once per run,
// from the branch that knows which handle actually ran; a nil handle or a failed
// transition returns false.
func (e *Executor) collectArtifacts(ctx context.Context, r *Run, handle *adapter.RunHandle, logWriter io.Writer) bool {
	if handle == nil {
		return false
	}
	if tErr := r.Transition(types.RunStateCollectingArtifacts); tErr != nil {
		return false
	}
	var lastErr error
	for attempt := 0; attempt < artifactCollectAttempts; attempt++ {
		artifacts, aErr := e.adapter.Artifacts(ctx, handle)
		if aErr == nil {
			r.Artifacts = artifacts
			return true
		}
		lastErr = aErr
		if attempt < artifactCollectAttempts-1 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(time.Duration(artifactRetryInterval.Load())):
			}
		}
	}
	if logWriter != nil {
		fmt.Fprintf(logWriter, "[dispatcher] warning: artifact collection failed after %d attempts: %v\n", artifactCollectAttempts, lastErr)
	}
	return false
}

// Execute runs the full lifecycle with guaranteed cleanup and panic recovery.
func (e *Executor) Execute(ctx context.Context, r *Run, logWriter io.Writer) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("executor panic: %v", rec)
			r.SetError(types.RunStateExecutionFailed, err)
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

	// Persist the (non-terminal) run record BEFORE provisioning. adapter.Execute
	// tags the VM with this run's plan id and then blocks for the whole provision
	// + run (minutes-to-hours for confidential runs). A concurrent `dispatcher gc`
	// keys its active-run protection off persisted records by plan id, so without
	// this write the live VM has no record, is misclassified as an orphan, and is
	// reaped mid-run.
	saveRun(r)

	// Bill the provisioning/staging phase, not only the running workload:
	// adapter.Execute provisions + uploads + starts the workload (minutes for a
	// cloud VM), and the billable clock starts at VM creation. Start the cost
	// sampler now — no handle exists yet, so a budget breach here cancels the
	// provisioning context to abort staging rather than terminating a handle.
	execCtx, cancelExec := context.WithCancel(ctx)
	defer cancelExec()
	stopProvSampler := e.startCostSampler(ctx, r, func() error { cancelExec(); return nil }, logWriter)

	handle, err := e.adapter.Execute(execCtx, r.Plan)
	stopProvSampler()
	if err != nil {
		// If the sampler tripped the budget mid-provisioning, the run is already
		// BudgetExceeded (terminal) — surface that, don't relabel it a workload
		// failure. The adapter's own teardown reclaims any partial provisioning.
		if r.GetState() == types.RunStateBudgetExceeded {
			saveRun(r)
			return fmt.Errorf("budget exceeded during provisioning (run %s)", r.ID)
		}
		// adapter.Execute is the provisioning + staging phase, so a failure here is
		// a provisioning failure (distinct in the record from a workload failure).
		r.SetError(types.RunStateProvisioningFailed, err)
		return fmt.Errorf("provisioning failed: %w", err)
	}
	// Stamp the run id onto the handle so adapters that need it (e.g.
	// CloudVMAdapter.Artifacts placing files under runs/<run-id>/) can
	// reach it without parsing handle.ID — which is provider-specific.
	handle.RunID = r.ID
	r.Handle = handle

	// The provisioning sampler could have tripped the budget as Execute was
	// completing (its terminate=cancelExec had no handle to kill then). The run is
	// now BudgetExceeded but a real VM exists — tear it down so it doesn't run
	// uncapped, and don't proceed into the ephemeral lifecycle on a terminal run.
	if r.GetState() == types.RunStateBudgetExceeded {
		e.attemptCleanup(context.Background(), r)
		saveRun(r)
		return fmt.Errorf("budget exceeded during provisioning (run %s)", r.ID)
	}

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

// supervision bundles the two per-handle background goroutines an ephemeral run
// needs — the cost sampler (budget enforcement) and the watchdog heartbeat — so a
// transient-failure retry can tear them down and re-arm them on the replacement
// handle as one unit, rather than juggling two stop functions in lockstep.
type supervision struct {
	stopSampler  func()
	stopWatchdog func()
}

func (s *supervision) stop() {
	s.stopSampler()
	s.stopWatchdog()
}

// superviseHandle starts the cost sampler and watchdog heartbeat bound to handle.
func (e *Executor) superviseHandle(ctx context.Context, r *Run, handle *adapter.RunHandle, logWriter io.Writer) *supervision {
	return &supervision{
		stopSampler:  e.startCostSampler(ctx, r, func() error { return e.adapter.Terminate(context.Background(), handle) }, logWriter),
		stopWatchdog: e.startEphemeralWatchdog(ctx, r, handle, logWriter),
	}
}

// externallyStopped reports whether another process (a `dispatcher stop`) has
// moved the persisted record to a stopping/terminal state. A transient retry must
// not resurrect such a run: the SIGTERM that `stop` sends is otherwise
// indistinguishable from cloud preemption, which we DO retry. Fails open (allows
// the retry) if the record can't be read.
func externallyStopped(runID string) bool {
	rec, err := LoadRecord(runID)
	if err != nil {
		return false
	}
	return rec.State == types.RunStateStopping || rec.State.IsTerminal()
}

// retryTransientFailure tears the failed attempt down and re-provisions once,
// re-arming supervision (via sup) on the new handle. The run stays in Running
// throughout so the budget keeps applying to the replacement VM. Returns the new
// handle, its terminal state + error, and whether the retry produced a healthy
// run. Supervision is stopped BEFORE teardown so a budget breach in the
// re-provision window can't trip BudgetExceeded on the destroyed handle and burn
// the run's only Running->BudgetExceeded transition.
func (e *Executor) retryTransientFailure(ctx context.Context, r *Run, sup *supervision, logWriter io.Writer) (*adapter.RunHandle, types.RunState, error, bool) {
	if logWriter != nil {
		fmt.Fprintln(logWriter, "[dispatcher] retrying transient failure once")
	}
	r.beginRetry()
	sup.stop()

	// Tear down the failed attempt so its VM/Job doesn't leak while re-provisioning;
	// drop r.Handle so a failed re-provision doesn't clean the dead handle twice.
	if _, cErr := e.adapter.Cleanup(context.Background(), r.Handle); cErr != nil {
		dlog.L().Warn("retry.cleanup.failed", "run", r.ID, "err", cErr.Error())
	}
	r.Handle = nil

	retryHandle, retryErr := e.adapter.Execute(ctx, r.Plan)
	if retryErr != nil {
		if logWriter != nil {
			fmt.Fprintf(logWriter, "[dispatcher] retry execute failed: %v\n", retryErr)
		}
		// Supervision is already stopped; leave sup as no-ops so the caller's
		// deferred sup.stop() is safe.
		*sup = supervision{stopSampler: func() {}, stopWatchdog: func() {}}
		return nil, types.RunStateExecutionFailed, nil, false
	}
	retryHandle.RunID = r.ID
	r.Handle = retryHandle
	_ = r.PersistHandle()
	*sup = *e.superviseHandle(ctx, r, retryHandle, logWriter) // re-arm on the new handle

	// We deliberately don't re-stream logs here — the original writer is closed.
	state, err := e.waitForTerminal(ctx, retryHandle, r.Plan.Constraints.MaxDuration)
	if err == nil && state != types.RunStateExecutionFailed {
		return retryHandle, state, nil, true
	}
	if fr, ok := e.adapter.(adapter.FailureReporter); ok {
		r.setFailure(fr.FailureDetails(retryHandle))
	}
	return retryHandle, state, err, false
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

	// Supervise the handle: the cost sampler (budget) and the watchdog heartbeat
	// run for as long as this executor owns the run. The watchdog matters because
	// Execute's setup TTL only covers provisioning; without a heartbeat a correct
	// long compute could self-destruct mid-run even though the CLI is attached. A
	// transient retry re-arms sup on the replacement handle; the deferred stop
	// calls through the pointer so it always tears down the current supervision.
	sup := e.superviseHandle(ctx, r, handle, logWriter)
	defer func() { sup.stop() }()

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

	// NOTE: we stay in Running (do NOT transition to CollectingArtifacts) until
	// after any transient-failure retry resolves, so the cost sampler can still
	// trip the budget on the re-provisioned VM (BudgetExceeded is legal only from
	// Running). Artifacts are collected per-branch below, from whichever handle
	// actually ran — crash dumps on failure, real outputs on (retry) success.

	// Capture failure details from the adapter if it supports rich reporting.
	// Always do this — we want the data on the run record for diagnose, even
	// if retry is disabled. classification gates the optional retry below.
	if err != nil || state == types.RunStateExecutionFailed {
		if fr, ok := e.adapter.(adapter.FailureReporter); ok {
			r.setFailure(fr.FailureDetails(handle))
		}
	}

	if err != nil {
		e.collectArtifacts(ctx, r, handle, logWriter) // crash dumps
		r.SetError(types.RunStateExecutionFailed, err)
		return fmt.Errorf("status check failed: %w", err)
	}
	if state == types.RunStateExecutionFailed {
		kind := adapter.ClassifyFailure(r.Failure)
		if logWriter != nil {
			fmt.Fprintf(logWriter, "[dispatcher] failure classified as %s: %s\n", kind, r.Failure.Message)
		}
		// Opt-in retry: only when the user explicitly asked AND the failure
		// looks transient AND we haven't already retried. Don't re-provision a run
		// the sampler already killed (BudgetExceeded is terminal).
		retrySucceeded := false
		if r.Plan.Constraints.RetryTransientFailures &&
			kind == adapter.FailureTransient &&
			r.RetryCount == 0 &&
			!r.GetState().IsTerminal() &&
			!externallyStopped(r.ID) {
			// state/err are consumed inside the helper; only the new handle and
			// success flag matter to the caller from here.
			handle, _, _, retrySucceeded = e.retryTransientFailure(ctx, r, sup, logWriter)
		}
		if !retrySucceeded {
			e.collectArtifacts(ctx, r, handle, logWriter) // crash dumps from the failed handle
			r.SetError(types.RunStateExecutionFailed, fmt.Errorf("workload execution failed"))
			return fmt.Errorf("workload execution failed")
		}
	}

	// Success (first attempt or retry): collect outputs from the handle that
	// actually completed — for a retry that's the re-provisioned VM.
	if !e.collectArtifacts(ctx, r, handle, logWriter) {
		// Output retrieval failed after retries. Do NOT tear the VM down — that
		// would destroy a finished job's outputs. Preserve it (it self-destructs
		// at the watchdog TTL, which is the recovery lease) and mark ArtifactFailed,
		// distinct from a workload failure. Suppress the deferred cleanup too.
		_ = r.Transition(types.RunStateArtifactFailed)
		saveRun(r)
		cleanupDone = true
		if logWriter != nil {
			fmt.Fprintf(logWriter, "[dispatcher] workload completed but outputs were not retrieved; VM preserved until its watchdog TTL — recover the outputs, then `dispatcher stop %s` to tear down\n", r.ID)
		}
		return fmt.Errorf("workload completed but output retrieval failed; VM preserved for recovery (run %s)", r.ID)
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

// startEphemeralWatchdog renews a durable target's self-destruct deadline for
// as long as an attached ephemeral run is being supervised. Renewal failures
// are warnings: provider Status and MaxDuration remain authoritative, while the
// remote watchdog still bounds cost if the CLI or network disappears.
func (e *Executor) startEphemeralWatchdog(ctx context.Context, r *Run,
	handle *adapter.RunHandle, logWriter io.Writer) func() {
	durable, ok := e.adapter.(adapter.DurableAdapter)
	if !ok {
		return func() {}
	}

	ttl := r.effectiveWatchdogTTL()
	interval := ttl / 3
	if interval <= 0 {
		interval = time.Millisecond
	}

	heartbeatCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	renew := func() {
		if _, err := durable.ExtendWatchdog(heartbeatCtx, handle, ttl); err != nil {
			if heartbeatCtx.Err() == nil && logWriter != nil {
				fmt.Fprintf(logWriter, "[dispatcher] warning: watchdog renewal failed: %v\n", err)
			}
			return
		}
		r.mu.Lock()
		r.LastHeartbeat = time.Now().UTC()
		r.mu.Unlock()
		saveRun(r)
	}

	// Renew before returning so a short configured TTL cannot expire between
	// setup completion and the first ticker firing.
	renew()
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				renew()
			}
		}
	}()

	return func() {
		cancel()
		wg.Wait()
	}
}

// waitForTerminal polls the adapter's Status until it returns a terminal state,
// the context is canceled, or maxDuration elapses. Blocking-Status adapters
// (local/docker) return terminal on the first call so the loop exits at once;
// poll-based durable adapters (cloud VM, k8s) return RunStateRunning until the
// workload finishes. On a maxDuration timeout the workload is terminated and
// reported failed; the watchdog is only a backstop for a crashed CLI.
// maxConsecutiveStatusErrors bounds how many transient Status failures the poll
// loop tolerates before giving up. At the default 3s interval this is ~15s of
// blips — enough to ride out a brief provider/network hiccup without stranding a
// run, short enough to surface a genuinely broken connection.
const maxConsecutiveStatusErrors = 5

func (e *Executor) waitForTerminal(ctx context.Context, handle *adapter.RunHandle, maxDuration time.Duration) (types.RunState, error) {
	var deadline <-chan time.Time
	if maxDuration > 0 {
		timer := time.NewTimer(maxDuration)
		defer timer.Stop()
		deadline = timer.C
	}

	// A Status error means "couldn't determine" (a dropped packet, an API 500, a
	// transient ssh failure), not "the workload failed". Tolerate a bounded number
	// of consecutive errors so a single blip during a multi-hour poll doesn't tear
	// down a healthy VM; only a real terminal state (or a sustained failure) ends
	// the run. The counter resets on any successful Status.
	consecutiveErrs := 0
	for {
		state, err := e.adapter.Status(ctx, handle)
		if err != nil {
			consecutiveErrs++
			if consecutiveErrs >= maxConsecutiveStatusErrors {
				return state, fmt.Errorf("status check failed %d times in a row: %w", consecutiveErrs, err)
			}
			dlog.L().Warn("status.transient_error",
				"handle", handle.ID, "consecutive", consecutiveErrs, "err", err.Error())
		} else {
			consecutiveErrs = 0
			if state != types.RunStateRunning {
				return state, nil
			}
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

// artifactRetryInterval is the backoff between artifact-collection attempts.
// Test-adjustable via SetArtifactRetryInterval.
var artifactRetryInterval atomic.Int64

// artifactCollectAttempts bounds how many times collectArtifacts retries a
// transient transport failure before giving up and preserving the VM.
const artifactCollectAttempts = 3

func init() {
	costSampleInterval.Store(int64(5 * time.Second))
	statusPollInterval.Store(int64(3 * time.Second))
	artifactRetryInterval.Store(int64(3 * time.Second))
}

// SetArtifactRetryInterval changes the artifact-collection backoff. Test-only;
// returns the previous value so the caller can restore it.
func SetArtifactRetryInterval(d time.Duration) time.Duration {
	return time.Duration(artifactRetryInterval.Swap(int64(d)))
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

// startCostSampler periodically computes the run's live cost and, if
// PlanConstraints.MaxEstimatedCostUSD is breached, transitions the run to
// BudgetExceeded and calls terminate to stop the billable work — Terminate on a
// running handle, or (during provisioning, before a handle exists) cancel of the
// provisioning context. Returns a stop function that cancels the sampler; callers
// must defer it.
func (e *Executor) startCostSampler(ctx context.Context, r *Run, terminate func() error, logWriter io.Writer) func() {
	budget := r.Plan.Constraints.MaxEstimatedCostUSD
	// Run the tracker whenever there's a budget to enforce OR a priced estimate to
	// surface live — so `list` and the persisted record reflect real-time spend
	// (not $0.00) and the billable clock survives a CLI crash. Skip only free or
	// unpriced runs (local, docker) where there's nothing to track or enforce.
	priced := r.Plan.Recommendation != nil && r.Plan.Recommendation.EstimatedCost.Value > 0
	if budget <= 0 && !priced {
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
				// Persist live spend each tick so `list`/the record track cost
				// through provisioning, run, and teardown — and survive a crash.
				r.setCost(live)
				saveRun(r)
				if budget <= 0 || live.Value <= budget {
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
				if termErr := terminate(); termErr != nil {
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
			// Drop the handle so a second cleanup pass (e.g. Execute's panic
			// recovery after executeEphemeral's deferred cleanup) is a no-op and
			// can't re-destroy an already-gone resource.
			r.Handle = nil
			_ = r.Transition(types.RunStateCompleted)
			return
		}

		if i < maxRetries-1 {
			time.Sleep(time.Duration(1<<uint(i)) * time.Second)
		}
	}
	// SetError is a no-op once the run is already terminal (e.g. ExecutionFailed
	// from the workload). Record the leaked-resource fact independently so it
	// surfaces on the run record even when the terminal state can't change —
	// otherwise a finished-looking run hides an undestroyed billing VM.
	r.setCleanupError(fmt.Sprintf("cleanup failed after %d retries", maxRetries))
	r.SetError(types.RunStateCleanupFailed, fmt.Errorf("cleanup failed after %d retries", maxRetries))
}
