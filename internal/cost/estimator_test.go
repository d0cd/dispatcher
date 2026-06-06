package cost

import (
	"context"
	"strings"
	"testing"

	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubFetcher struct {
	provider  cloudvm.ProviderID
	instances []cloudvm.InstanceType
}

func (s *stubFetcher) Provider() cloudvm.ProviderID { return s.provider }
func (s *stubFetcher) Fetch(context.Context) ([]cloudvm.InstanceType, error) {
	return s.instances, nil
}

func TestEstimateCost_LocalDocker(t *testing.T) {
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}
	target := types.TargetConfig{
		Capabilities: types.Capabilities{
			Accounting: types.AccountingCapability{RateCard: "local"},
		},
	}

	est := EstimateCost(w, target, nil)
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

	est := EstimateCost(w, target, nil)
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
			Accounting: types.AccountingCapability{RateCard: "aws"},
		},
	}

	est := EstimateCost(w, target, nil)
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

	est := EstimateCost(w, target, nil)
	assert.Equal(t, types.ConfidenceUnknown, est.Confidence)
}

// TestEstimateCost_LiveCatalog verifies that a cloud-vm target with a non-nil
// catalog uses the cheapest matching instance's price rather than the static
// rate card.
func TestEstimateCost_LiveCatalog(t *testing.T) {
	cat, _, err := cloudvm.NewLiveCatalog(context.Background(), &stubFetcher{
		provider: cloudvm.ProviderHetzner,
		instances: []cloudvm.InstanceType{
			{Name: "cx22", Provider: cloudvm.ProviderHetzner, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.006, Arch: "x86_64"},
			{Name: "cx32", Provider: cloudvm.ProviderHetzner, VCPUs: 4, MemoryGB: 8, PricePerHour: 0.011, Arch: "x86_64"},
		},
	})
	require.NoError(t, err)

	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Requirements: types.ResourceRequirements{CPU: "2"},
	}
	target := types.TargetConfig{
		Kind: types.TargetKindCloudVM,
		Capabilities: types.Capabilities{
			Accounting: types.AccountingCapability{RateCard: "hetzner"},
		},
	}

	est := EstimateCost(w, target, cat)
	// 1h × $0.006 = $0.006, rounded to cents = $0.00.
	assert.InDelta(t, 0.0, est.Value, 0.01)
	assert.Equal(t, types.ConfidenceMedium, est.Confidence)
	require.NotEmpty(t, est.Assumptions)
	assert.Contains(t, est.Assumptions[0], "cx22", "should pick the cheapest matching instance")
}

// TestEstimateCost_LiveCatalog_FallsBackWhenEmpty verifies that a catalog
// with no matching instances falls back to the static rate card rather than
// returning ConfidenceUnknown.
func TestEstimateCost_LiveCatalog_FallsBackWhenEmpty(t *testing.T) {
	// Catalog contains AWS instances, but the target asks for Hetzner.
	cat, _, err := cloudvm.NewLiveCatalog(context.Background(), &stubFetcher{
		provider: cloudvm.ProviderAWS,
		instances: []cloudvm.InstanceType{
			{Name: "t3.micro", Provider: cloudvm.ProviderAWS, VCPUs: 2, MemoryGB: 1, PricePerHour: 0.0104},
		},
	})
	require.NoError(t, err)

	target := types.TargetConfig{
		Kind: types.TargetKindCloudVM,
		Capabilities: types.Capabilities{
			Accounting: types.AccountingCapability{RateCard: "hetzner"},
		},
	}
	w := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}

	est := EstimateCost(w, target, cat)
	// Falls back to the "hetzner" static rate card → ConfidenceLow because
	// fallback cloud estimates are stale (no live data).
	assert.Equal(t, types.ConfidenceLow, est.Confidence)
	require.NotEmpty(t, est.Assumptions)
	var hasFallbackNote bool
	for _, a := range est.Assumptions {
		if strings.Contains(a, "fallback") {
			hasFallbackNote = true
		}
	}
	assert.True(t, hasFallbackNote, "fallback estimate should flag itself in Assumptions")
}

func TestParseCPU(t *testing.T) {
	assert.Equal(t, 2, parseCPU("2"))
	assert.Equal(t, 4, parseCPU("4"))
	assert.Equal(t, 2, parseCPU(""))    // default
	assert.Equal(t, 2, parseCPU("abc")) // default
}
