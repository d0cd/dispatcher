package cost

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestEstimateCost_LocalDocker(t *testing.T) {
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	target := types.TargetConfig{
		Capabilities: types.Capabilities{
			Accounting: types.AccountingCapability{RateCard: "local"},
		},
	}

	est := EstimateCost(w, target)
	assert.Equal(t, 0.0, est.Value)
	assert.Equal(t, types.ConfidenceHigh, est.Confidence)
}

func TestEstimateCost_KubernetesService(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindService,
		Requirements: types.ResourceRequirements{CPU: "2"},
	}
	target := types.TargetConfig{
		Capabilities: types.Capabilities{
			Accounting: types.AccountingCapability{RateCard: "internal"},
		},
	}

	est := EstimateCost(w, target)
	assert.Greater(t, est.Value, 0.0)
	assert.Equal(t, "USD", est.Currency)
	assert.Equal(t, types.ConfidenceMedium, est.Confidence)
	assert.Contains(t, est.Assumptions[0], "24h")
}

func TestEstimateCost_GPUJob(t *testing.T) {
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindGPUJob,
		Requirements: types.ResourceRequirements{
			GPU: types.GPURequirement{Required: true, Count: 1},
		},
	}
	target := types.TargetConfig{
		Capabilities: types.Capabilities{
			Accounting: types.AccountingCapability{RateCard: "modal"},
		},
	}

	est := EstimateCost(w, target)
	assert.Greater(t, est.Value, 0.0)
	assert.Equal(t, types.ConfidenceLow, est.Confidence)
}

func TestEstimateCost_UnknownRateCard(t *testing.T) {
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	target := types.TargetConfig{
		Capabilities: types.Capabilities{
			Accounting: types.AccountingCapability{RateCard: "nonexistent"},
		},
	}

	est := EstimateCost(w, target)
	assert.Equal(t, types.ConfidenceUnknown, est.Confidence)
}

func TestParseCPU(t *testing.T) {
	assert.Equal(t, 2, parseCPU("2"))
	assert.Equal(t, 4, parseCPU("4"))
	assert.Equal(t, 2, parseCPU(""))   // default
	assert.Equal(t, 2, parseCPU("abc")) // default
}
