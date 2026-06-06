package run

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/types"
)

// LifecycleMode determines teardown behavior.
type LifecycleMode string

const (
	LifecycleEphemeral   LifecycleMode = "ephemeral"
	LifecycleLongRunning LifecycleMode = "long-running"
)

// LifecycleForWorkload returns the lifecycle mode based on workload kind.
func LifecycleForWorkload(kind types.WorkloadKind) LifecycleMode {
	if kind == types.WorkloadKindService {
		return LifecycleLongRunning
	}
	return LifecycleEphemeral
}

// Run tracks the full lifecycle of a workload execution.
type Run struct {
	mu sync.RWMutex

	ID         string
	PlanID     string
	TargetID   string
	Owner      string
	State      types.RunState
	Plan       *types.Plan
	Handle     *adapter.RunHandle
	StartedAt  time.Time
	FinishedAt time.Time
	Error      string
	Logs       []adapter.LogEvent
	Artifacts  []adapter.ArtifactRef
	Cost       types.CostEstimate

	// Durable execution fields
	HandleID      string            // persisted handle identifier
	HandleState   json.RawMessage   // serialized adapter state for reconnection
	Lifecycle     LifecycleMode     // ephemeral or long-running
	WatchdogTTL   time.Duration     // cloud-init self-destruct TTL
	LastHeartbeat time.Time         // last watchdog extension
	LogFile       string            // path to local log cache
}

// NewRun creates a run in the Created state.
func NewRun(plan *types.Plan) *Run {
	return &Run{
		ID:       generateRunID(),
		PlanID:   plan.Metadata.ID,
		TargetID: plan.Recommendation.Target,
		Owner:    plan.Metadata.CreatedBy,
		State:    types.RunStateCreated,
		Plan:     plan,
	}
}

// Transition moves the run to a new state, enforcing valid transitions.
func (r *Run) Transition(to types.RunState) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.State.IsTerminal() {
		return fmt.Errorf("cannot transition from terminal state %s", r.State)
	}

	if !isValidTransition(r.State, to) {
		return fmt.Errorf("invalid transition from %s to %s", r.State, to)
	}

	from := r.State
	r.State = to

	if to == types.RunStateRunning && r.StartedAt.IsZero() {
		r.StartedAt = time.Now().UTC()
	}
	if to.IsTerminal() {
		r.FinishedAt = time.Now().UTC()
	}

	dlog.L().Info("run.transition", "run", r.ID, "from", string(from), "to", string(to))
	return nil
}

// SetError records an error and transitions to a failure state.
func (r *Run) SetError(state types.RunState, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.State = state
	r.Error = err.Error()
	r.FinishedAt = time.Now().UTC()
}

// GetState returns the current run state (thread-safe).
func (r *Run) GetState() types.RunState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.State
}

// PersistHandle serializes the adapter handle state for durable storage.
// If the handle's State implements SerializableState, it is marshaled.
func (r *Run) PersistHandle() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.Handle == nil {
		return nil
	}

	r.HandleID = r.Handle.ID

	if ss, ok := r.Handle.State.(adapter.SerializableState); ok {
		raw, err := ss.MarshalHandleState()
		if err != nil {
			return fmt.Errorf("cannot serialize handle state: %w", err)
		}
		r.HandleState = raw
	}

	return nil
}

// validTransitions defines the allowed state machine transitions.
var validTransitions = map[types.RunState][]types.RunState{
	types.RunStateCreated: {
		types.RunStatePlanning,
		types.RunStatePlanInvalid,
	},
	types.RunStatePlanning: {
		types.RunStateValidated,
		types.RunStatePlanInvalid,
	},
	types.RunStateValidated: {
		types.RunStateAwaitingApproval,
		types.RunStatePreparing,
	},
	types.RunStateAwaitingApproval: {
		types.RunStatePreparing,
		types.RunStateApprovalDenied,
	},
	types.RunStatePreparing: {
		types.RunStateRunning,
		types.RunStatePackageFailed,
		types.RunStateProvisioningFailed,
	},
	types.RunStateRunning: {
		types.RunStateCollectingArtifacts,
		types.RunStateExecutionFailed,
		types.RunStateBudgetExceeded,
		types.RunStateDetached,
		types.RunStateStopping,
	},
	types.RunStateDetached: {
		types.RunStateReconnecting,
		types.RunStateCleaningUp,
	},
	types.RunStateReconnecting: {
		types.RunStateRunning,
		types.RunStateDetached,
		types.RunStateCleaningUp,
	},
	types.RunStateStopping: {
		types.RunStateCleaningUp,
		types.RunStateCleanupFailed,
	},
	types.RunStateBudgetExceeded: {
		types.RunStateCleaningUp,
		types.RunStateCleanupFailed,
	},
	types.RunStateCollectingArtifacts: {
		types.RunStateReconcilingCost,
		types.RunStateArtifactFailed,
	},
	types.RunStateReconcilingCost: {
		types.RunStateCleaningUp,
		types.RunStateCostUnknown,
	},
	types.RunStateCleaningUp: {
		types.RunStateCompleted,
		types.RunStateCleanupFailed,
	},
}

func isValidTransition(from, to types.RunState) bool {
	allowed, ok := validTransitions[from]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == to {
			return true
		}
	}
	return false
}

func generateRunID() string {
	return "run_" + types.ShortID()
}
