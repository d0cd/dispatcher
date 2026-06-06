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

	risks := Analyze(w, target, est)
	categories := riskCategories(risks)
	assert.Contains(t, categories, "cost-uncertainty")
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

	risks := Analyze(w, target, est)
	categories := riskCategories(risks)
	assert.Contains(t, categories, "capacity-risk")
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

	risks := Analyze(w, target, est)
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

	risks := Analyze(w, target, est)
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

	risks := Analyze(w, target, est)
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

	risks := Analyze(w, target, est)
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
