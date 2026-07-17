package policy

import "github.com/d0cd/dispatcher/internal/types"

// DefaultCostAutoApproveUSD is the threshold under which runs auto-approve.
const DefaultCostAutoApproveUSD = 5.0

// Evaluate returns the approval requirements for a plan.
func Evaluate(w types.WorkloadSpec, t types.TargetConfig, est types.CostEstimate) []types.PolicyRequirement {
	var reqs []types.PolicyRequirement

	// Unknown cost requires approval
	if est.Confidence == types.ConfidenceUnknown {
		reqs = append(reqs, types.PolicyRequirement{
			Name:   "unknown-cost",
			Reason: "cost estimate is unknown; approval required before execution",
		})
	}

	// High cost requires approval
	if est.Value > DefaultCostAutoApproveUSD {
		reqs = append(reqs, types.PolicyRequirement{
			Name:   "cost-approval",
			Reason: "estimated cost exceeds auto-approve threshold",
		})
	}

	// GPU requires approval
	if w.Requirements.GPU.Required {
		reqs = append(reqs, types.PolicyRequirement{
			Name:   "gpu-approval",
			Reason: "GPU workloads require approval",
		})
	}

	// Public endpoint requires approval
	if w.DetectedKind == types.WorkloadKindService && t.Capabilities.Networking.PublicEndpoint {
		reqs = append(reqs, types.PolicyRequirement{
			Name:   "public-endpoint",
			Reason: "public endpoint exposure requires approval",
		})
	}

	// External provider with secrets requires approval
	if len(w.Secrets) > 0 && isExternalProvider(t) {
		reqs = append(reqs, types.PolicyRequirement{
			Name:   "secrets-on-external",
			Reason: "workload uses secrets on an external provider; approval required",
		})
	}

	return reqs
}

// isExternalProvider reports whether the target ships the workload (and its
// secrets) off the local machine — any non-local kind. Kubernetes clusters and
// imported SSH hosts are just as external as a cloud VM, so secrets on them
// require the same approval.
func isExternalProvider(t types.TargetConfig) bool {
	switch t.Kind {
	case types.TargetKindCloudVM, types.TargetKindKubernetes, types.TargetKindSSH:
		return true
	default:
		return false
	}
}
