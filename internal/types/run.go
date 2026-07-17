package types

// RunState represents the current state of a run.
type RunState string

const (
	RunStateCreated             RunState = "created"
	RunStatePlanning            RunState = "planning"
	RunStateValidated           RunState = "validated"
	RunStateAwaitingApproval    RunState = "awaiting-approval"
	RunStatePreparing           RunState = "preparing"
	RunStateRunning             RunState = "running"
	RunStateCollectingArtifacts RunState = "collecting-artifacts"
	RunStateReconcilingCost     RunState = "reconciling-cost"
	RunStateCleaningUp          RunState = "cleaning-up"
	RunStateCompleted           RunState = "completed"

	// Durable execution states.
	RunStateStopping RunState = "stopping" // user requested stop

	// Failure states.
	RunStatePlanInvalid        RunState = "plan-invalid"
	RunStateApprovalDenied     RunState = "approval-denied"
	RunStatePackageFailed      RunState = "package-failed"
	RunStateProvisioningFailed RunState = "provisioning-failed"
	RunStateExecutionFailed    RunState = "execution-failed"
	RunStateBudgetExceeded     RunState = "budget-exceeded"
	RunStateArtifactFailed     RunState = "artifact-failed"
	RunStateCleanupFailed      RunState = "cleanup-failed"
	RunStateCostUnknown        RunState = "cost-unknown"
)

// IsTerminal returns true if the run state is a final state.
func (s RunState) IsTerminal() bool {
	switch s {
	case RunStateCompleted,
		RunStatePlanInvalid,
		RunStateApprovalDenied,
		RunStatePackageFailed,
		RunStateProvisioningFailed,
		RunStateExecutionFailed,
		RunStateBudgetExceeded,
		RunStateArtifactFailed,
		RunStateCleanupFailed,
		RunStateCostUnknown:
		return true
	}
	return false
}

// IsFailure returns true if the run state indicates a failure.
func (s RunState) IsFailure() bool {
	switch s {
	case RunStatePlanInvalid,
		RunStateApprovalDenied,
		RunStatePackageFailed,
		RunStateProvisioningFailed,
		RunStateExecutionFailed,
		RunStateBudgetExceeded,
		RunStateArtifactFailed,
		RunStateCleanupFailed,
		RunStateCostUnknown:
		return true
	}
	return false
}
