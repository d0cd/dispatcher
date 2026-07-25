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

// ResourceKind classifies a billable cloud resource for the GC/cost audit.
type ResourceKind string

const (
	ResourceInstance ResourceKind = "instance"
	ResourceDisk     ResourceKind = "disk"
	ResourceImage    ResourceKind = "image"
	ResourceSnapshot ResourceKind = "snapshot"
	ResourceAddress  ResourceKind = "address"  // reserved/static IP
	ResourceFirewall ResourceKind = "firewall" // security group / NSG
	// ResourceContainerImage is a pushed container image / registry repository
	// (e.g. GCP Artifact Registry) — the measured agent image for confidential runs.
	ResourceContainerImage ResourceKind = "container-image"
)

// ResourceInfo describes a cloud resource for GC and the cost audit.
type ResourceInfo struct {
	ResourceID   string            `json:"resourceId"`
	Provider     string            `json:"provider"`
	Kind         ResourceKind      `json:"kind"`
	Region       string            `json:"region"`
	InstanceType string            `json:"instanceType,omitempty"`
	CreatedAt    time.Time         `json:"createdAt"`
	RunID        string            `json:"runId,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	// Scope is the provider sub-scope the resource actually lives in — an Azure
	// resource group or a GCP project — captured when gc scans beyond the
	// adapter's configured scope. Destroy routes to it (empty = adapter default).
	Scope string `json:"scope,omitempty"`
	// MonthlyUSD is the estimated ongoing cost of this resource (0 if free or
	// unknown). Instances report their hourly rate as a monthly figure only as a
	// worst-case; the real ongoing concern is persistent disks/images/IPs.
	MonthlyUSD float64 `json:"monthlyUsd,omitempty"`
}

// DispatcherOwned reports whether dispatcher created this resource — the hard
// boundary for any destructive action. GC lists non-owned resources (cost
// visibility) but must never modify them. dispatcher tags everything it creates
// with dispatcher=true.
func (r ResourceInfo) DispatcherOwned() bool {
	return r.Tags["dispatcher"] == "true"
}

// DurableAdapter extends TargetAdapter with reconnection and resource management.
// Adapters that manage remote/cloud resources should implement this.
type DurableAdapter interface {
	TargetAdapter

	// Reconnect rebuilds a RunHandle from persisted state after CLI restart.
	Reconnect(ctx context.Context, handleID string, state json.RawMessage) (*RunHandle, error)

	// ExtendWatchdog extends the self-destruct timer on the remote resource.
	ExtendWatchdog(ctx context.Context, h *RunHandle, ttl time.Duration) (time.Time, error)

	// ListResources returns every dispatcher-tagged billable resource this
	// adapter can enumerate (instances and, where implemented, disks/images/
	// snapshots/addresses/firewalls), each with Kind + MonthlyUSD, for GC and
	// the cost audit.
	ListResources(ctx context.Context) ([]ResourceInfo, error)

	// DestroyResource destroys a resource returned by ListResources, dispatching
	// on its Kind. Implementations MUST refuse a resource that is not
	// DispatcherOwned() — the hard boundary against touching another owner's
	// infrastructure.
	DestroyResource(ctx context.Context, res ResourceInfo) error
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
	Reclaimed bool   // the spot/preemptible instance was reclaimed by the provider mid-run
	Message   string // one-line human explanation
}

// FailureReporter is optional. Adapters that don't implement it get a
// zero-value FailureDetails → classifyFailure says "unknown" → no retry.
type FailureReporter interface {
	FailureDetails(h *RunHandle) FailureDetails
}
