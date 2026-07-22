package risk

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestAnalyze_LowConfidenceCost(t *testing.T) {
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	target := types.TargetConfig{}
	est := types.CostEstimate{Confidence: types.ConfidenceLow}

	risks := Analyze(w, target, est, false)
	categories := riskCategories(risks)
	assert.Contains(t, categories, "cost-uncertainty")
}

func TestAnalyze_ConfidentialDiskResidual(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Requirements: types.ResourceRequirements{
			Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp"},
		},
	}
	assert.Contains(t, riskCategories(Analyze(w, types.TargetConfig{}, types.CostEstimate{}, false)), "confidential-disk-residual")

	plain := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	assert.NotContains(t, riskCategories(Analyze(plain, types.TargetConfig{}, types.CostEstimate{}, false)), "confidential-disk-residual")
}

func TestAnalyze_GPUCapacityRisk(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindGPUJob,
		Requirements: types.ResourceRequirements{
			GPU: types.GPURequirement{Required: true},
		},
	}
	target := types.TargetConfig{}
	est := types.CostEstimate{Confidence: types.ConfidenceMedium}

	risks := Analyze(w, target, est, false)
	categories := riskCategories(risks)
	assert.Contains(t, categories, "capacity-risk")
}

// A GPU workload whose cost estimate resolved no instance type (no catalog
// match) will be refused at run time, so plan must flag it.
func TestAnalyze_GPURequiredButNoInstanceResolved(t *testing.T) {
	w := types.WorkloadSpec{
		Requirements: types.ResourceRequirements{GPU: types.GPURequirement{Required: true, Model: "h100"}},
	}
	target := types.TargetConfig{Kind: types.TargetKindCloudVM}
	est := types.CostEstimate{InstanceType: ""}

	categories := riskCategories(Analyze(w, target, est, false))
	assert.Contains(t, categories, "gpu-unschedulable")
}

func TestAnalyze_NoGPUUnschedulableRiskWhenInstanceResolved(t *testing.T) {
	w := types.WorkloadSpec{
		Requirements: types.ResourceRequirements{GPU: types.GPURequirement{Required: true, Model: "a100"}},
	}
	target := types.TargetConfig{Kind: types.TargetKindCloudVM}
	est := types.CostEstimate{InstanceType: "a2-highgpu-1g"}

	categories := riskCategories(Analyze(w, target, est, false))
	assert.NotContains(t, categories, "gpu-unschedulable")
}

func TestAnalyze_SecretRisk(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Secrets: []types.SecretRef{
			{Kind: "api-key", Name: "API_KEY"},
		},
	}
	target := types.TargetConfig{}
	est := types.CostEstimate{Confidence: types.ConfidenceMedium}

	risks := Analyze(w, target, est, false)
	categories := riskCategories(risks)
	assert.Contains(t, categories, "credential-risk")
}

func TestAnalyze_DataEgressRisk(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Data: []types.DataRequirement{
			{Kind: "s3", Details: "s3://my-bucket"},
		},
	}
	target := types.TargetConfig{}
	est := types.CostEstimate{Confidence: types.ConfidenceMedium}

	risks := Analyze(w, target, est, false)
	categories := riskCategories(risks)
	assert.Contains(t, categories, "data-egress-risk")
}

func TestAnalyze_PublicEndpointRisk(t *testing.T) {
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindService}
	target := types.TargetConfig{
		Capabilities: types.Capabilities{
			Networking: types.NetworkingCapability{PublicEndpoint: true},
		},
	}
	est := types.CostEstimate{Confidence: types.ConfidenceMedium}

	risks := Analyze(w, target, est, false)
	categories := riskCategories(risks)
	assert.Contains(t, categories, "public-endpoint-risk")
}

func TestAnalyze_PackageRisk(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Package: types.PackagePlan{
			BuildRequired: true,
			Dockerfile:    "", // no Dockerfile
		},
	}
	target := types.TargetConfig{}
	est := types.CostEstimate{Confidence: types.ConfidenceMedium}

	risks := Analyze(w, target, est, false)
	categories := riskCategories(risks)
	assert.Contains(t, categories, "package-risk")
}

func riskCategories(risks []types.Risk) []string {
	cats := make([]string, len(risks))
	for i, r := range risks {
		cats[i] = r.Category
	}
	return cats
}

func TestAnalyze_SpotInterruptionRisk(t *testing.T) {
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindJob}
	target := types.TargetConfig{}
	est := types.CostEstimate{Confidence: types.ConfidenceMedium}

	// spot=true surfaces the reclaim risk; on-demand does not.
	assert.Contains(t, riskCategories(Analyze(w, target, est, true)), "spot-interruption")
	assert.NotContains(t, riskCategories(Analyze(w, target, est, false)), "spot-interruption")
}
