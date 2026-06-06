package adapter

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
)

// LogEvent represents a single log line from a running workload.
type LogEvent struct {
	Stream  string // "stdout" or "stderr"
	Message string
}

// ArtifactRef is a reference to an output artifact from a run.
type ArtifactRef struct {
	Name string
	Path string
	Size int64
}

// CleanupResult describes the outcome of cleaning up run resources.
type CleanupResult struct {
	Success          bool
	ResourcesCleaned []string
	Errors           []string
}

// ResourceAccounting tracks resource usage for a run.
type ResourceAccounting struct {
	EstimatedCost  types.CostEstimate
	RuntimeSeconds float64
}

// RunHandle identifies a running workload instance.
type RunHandle struct {
	ID       string
	TargetID string
	State    interface{} // adapter-specific opaque state
	RunID    string      // set post-Execute for artifact-tree routing
}

// SerializableState lets adapter state survive CLI restarts. When
// RunHandle.State implements this, the executor persists it.
type SerializableState interface {
	MarshalHandleState() (json.RawMessage, error)
}

// ResourceInfo describes a cloud resource managed by an adapter.
type ResourceInfo struct {
	ResourceID   string            `json:"resourceId"`
	Provider     string            `json:"provider"`
	Region       string            `json:"region"`
	InstanceType string            `json:"instanceType"`
	CreatedAt    time.Time         `json:"createdAt"`
	RunID        string            `json:"runId,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
}

// DurableAdapter extends TargetAdapter with reconnection and resource management.
// Adapters that manage remote/cloud resources should implement this.
type DurableAdapter interface {
	TargetAdapter

	// Reconnect rebuilds a RunHandle from persisted state after CLI restart.
	Reconnect(ctx context.Context, handleID string, state json.RawMessage) (*RunHandle, error)

	// ExtendWatchdog extends the self-destruct timer on the remote resource.
	ExtendWatchdog(ctx context.Context, h *RunHandle, ttl time.Duration) (time.Time, error)

	// ListResources returns all resources this adapter manages, for GC.
	ListResources(ctx context.Context) ([]ResourceInfo, error)

	// DestroyResource forcibly destroys a resource by its provider-specific ID.
	DestroyResource(ctx context.Context, resourceID string) error
}

// TargetAdapter is the interface every execution target must implement.
type TargetAdapter interface {
	// ID returns the target identifier.
	ID() string

	// Validate checks if the workload can run on this target.
	Validate(ctx context.Context, w types.WorkloadSpec) (types.ValidationResult, error)

	// EstimateCost returns a cost estimate for this workload.
	EstimateCost(ctx context.Context, w types.WorkloadSpec) (types.CostEstimate, error)

	// Prepare sets up resources needed before execution (e.g., build image).
	Prepare(ctx context.Context, p *types.Plan) error

	// Execute starts the workload and returns a handle to track it.
	Execute(ctx context.Context, p *types.Plan) (*RunHandle, error)

	// Status returns the current run state.
	Status(ctx context.Context, h *RunHandle) (types.RunState, error)

	// Logs streams log events from the running workload.
	Logs(ctx context.Context, h *RunHandle, w io.Writer) error

	// Artifacts returns references to output artifacts.
	Artifacts(ctx context.Context, h *RunHandle) ([]ArtifactRef, error)

	// Terminate stops a running workload.
	Terminate(ctx context.Context, h *RunHandle) error

	// Cleanup releases all resources associated with the run.
	Cleanup(ctx context.Context, h *RunHandle) (*CleanupResult, error)
}

// FailureDetails is the adapter's best-effort post-mortem; classifyFailure
// keys off it to decide whether a retry is appropriate. Only consulted
// when run state is ExecutionFailed (ExitCode=0 also means "unknown").
type FailureDetails struct {
	ExitCode  int    // process exit code
	Signal    string // "SIGKILL", "SIGSEGV", etc.; empty for normal exit
	OOMKilled bool   // runtime-confirmed OOM (docker/k8s); local can only infer from SIGKILL
	Message   string // one-line human explanation
}

// FailureReporter is optional. Adapters that don't implement it get a
// zero-value FailureDetails → classifyFailure says "unknown" → no retry.
type FailureReporter interface {
	FailureDetails(h *RunHandle) FailureDetails
}
