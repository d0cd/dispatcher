package run

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/plan"
)

// RenewWatchdog extends the run's cloud self-destruct watchdog by its effective
// TTL and records the heartbeat, so a healthy detached run isn't reaped while
// dispatcher is still watching it. It refuses terminal runs and targets without
// a watchdog (non-durable adapters). The caller persists the run.
func RenewWatchdog(ctx context.Context, a adapter.TargetAdapter, r *Run) (time.Time, error) {
	if r.GetState().IsTerminal() {
		return time.Time{}, fmt.Errorf("run %s is %s; nothing to renew", r.ID, r.GetState())
	}
	durable, ok := a.(adapter.DurableAdapter)
	if !ok {
		return time.Time{}, fmt.Errorf("target %s has no watchdog to renew", r.TargetID)
	}
	ttl := r.effectiveWatchdogTTL()
	deadline, err := durable.ExtendWatchdog(ctx, r.Handle, ttl)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to renew watchdog for run %s: %w", r.ID, err)
	}
	r.LastHeartbeat = time.Now().UTC()
	return deadline, nil
}

// AdapterResolver resolves a target ID to an adapter instance.
type AdapterResolver func(targetID string) (adapter.TargetAdapter, error)

// ReconnectToRun loads a persisted RunRecord, resolves the adapter,
// rebuilds the RunHandle via the adapter's Reconnect method, and returns
// a live Run object with its adapter.
func ReconnectToRun(ctx context.Context, runID string, resolve AdapterResolver) (*Run, adapter.TargetAdapter, error) {
	record, err := LoadRecord(runID)
	if err != nil {
		return nil, nil, err
	}

	r := RunFromRecord(record)

	// If terminal, no reconnection needed
	if record.State.IsTerminal() {
		return r, nil, nil
	}

	// Resolve adapter
	a, err := resolve(record.TargetID)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot resolve adapter for target %q: %w", record.TargetID, err)
	}

	// Check if adapter supports reconnection
	durable, ok := a.(adapter.DurableAdapter)
	if !ok {
		// Non-durable adapter — can't reconnect, but return what we have
		return r, a, nil
	}

	// Need persisted handle state to reconnect
	if record.HandleState == nil || record.HandleID == "" {
		return r, a, fmt.Errorf("run %s has no persisted handle state for reconnection", runID)
	}

	// Reconnect: rebuild RunHandle from persisted state
	handle, err := durable.Reconnect(ctx, record.HandleID, record.HandleState)
	if err != nil {
		return r, a, fmt.Errorf("reconnection failed: %w", err)
	}
	r.Handle = handle

	// Load the plan from plan store
	if p, err := plan.Load(record.PlanID); err == nil {
		r.Plan = p
	}

	return r, a, nil
}

// RunFromRecord reconstructs a Run from a persisted RunRecord.
// The returned Run has no Handle or Plan — those must be recovered separately.
func RunFromRecord(rec *RunRecord) *Run {
	return &Run{
		ID:            rec.ID,
		PlanID:        rec.PlanID,
		TargetID:      rec.TargetID,
		Owner:         rec.Owner,
		State:         rec.State,
		StartedAt:     rec.StartedAt,
		FinishedAt:    rec.FinishedAt,
		Error:         rec.Error,
		Cost:          rec.Cost,
		Failure:       rec.Failure,
		RetryCount:    rec.RetryCount,
		Timeline:      rec.Timeline,
		HandleID:      rec.HandleID,
		HandleState:   json.RawMessage(rec.HandleState),
		Lifecycle:     rec.Lifecycle,
		WatchdogTTL:   rec.WatchdogTTL,
		LastHeartbeat: rec.LastHeartbeat,
		LogFile:       rec.LogFile,
		Approval:      rec.Approval,
	}
}
