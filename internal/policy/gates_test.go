package policy

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestEvaluate_CheapJobNoApprovals(t *testing.T) {
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	target := types.TargetConfig{Kind: types.TargetKindDocker}
	est := types.CostEstimate{Value: 0.0, Confidence: types.ConfidenceHigh}

	reqs := Evaluate(w, target, est)
	assert.Empty(t, reqs)
}

func TestEvaluate_HighCostRequiresApproval(t *testing.T) {
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	target := types.TargetConfig{Kind: types.TargetKindDocker}
	est := types.CostEstimate{Value: 10.0, Confidence: types.ConfidenceMedium}

	reqs := Evaluate(w, target, est)
	names := approvalNames(reqs)
	assert.Contains(t, names, "cost-approval")
}

func TestEvaluate_UnknownCostRequiresApproval(t *testing.T) {
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	target := types.TargetConfig{Kind: types.TargetKindDocker}
	est := types.CostEstimate{Confidence: types.ConfidenceUnknown}

	reqs := Evaluate(w, target, est)
	names := approvalNames(reqs)
	assert.Contains(t, names, "unknown-cost")
}

func TestEvaluate_GPURequiresApproval(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindGPUJob,
		Requirements: types.ResourceRequirements{
			GPU: types.GPURequirement{Required: true},
		},
	}
	target := types.TargetConfig{Kind: types.TargetKindKubernetes}
	est := types.CostEstimate{Value: 3.0, Confidence: types.ConfidenceMedium}

	reqs := Evaluate(w, target, est)
	names := approvalNames(reqs)
	assert.Contains(t, names, "gpu-approval")
}

func TestEvaluate_PublicEndpointRequiresApproval(t *testing.T) {
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindService}
	target := types.TargetConfig{
		Kind: types.TargetKindKubernetes,
		Capabilities: types.Capabilities{
			Networking: types.NetworkingCapability{PublicEndpoint: true},
		},
	}
	est := types.CostEstimate{Value: 3.0, Confidence: types.ConfidenceMedium}

	reqs := Evaluate(w, target, est)
	names := approvalNames(reqs)
	assert.Contains(t, names, "public-endpoint")
}

func TestEvaluate_SecretsOnExternalProvider(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Secrets:      []types.SecretRef{{Kind: "api-key", Name: "KEY"}},
	}
	target := types.TargetConfig{Kind: types.TargetKindCloudVM}
	est := types.CostEstimate{Value: 3.0, Confidence: types.ConfidenceMedium}

	reqs := Evaluate(w, target, est)
	names := approvalNames(reqs)
	assert.Contains(t, names, "secrets-on-external")
}

func approvalNames(reqs []types.PolicyRequirement) []string {
	names := make([]string, len(reqs))
	for i, r := range reqs {
		names[i] = r.Name
	}
	return names
}
