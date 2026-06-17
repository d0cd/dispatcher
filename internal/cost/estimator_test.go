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

func TestEstimateCost_IncludesMemory(t *testing.T) {
	target := types.TargetConfig{
		Capabilities: types.Capabilities{
			Accounting: types.AccountingCapability{RateCard: "internal"},
		},
	}

	// internal rate card: Base 0.02 + CPU 0.04*2 + Mem 0.005*4 = 0.12 for 1h.
	withMem := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindJob,
		Requirements: types.ResourceRequirements{CPU: "2", Memory: "4G"},
	}
	assert.InDelta(t, 0.12, EstimateCost(withMem, target, nil).Value, 0.0001)

	// Unspecified memory adds nothing (no memory term).
	noMem := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindJob,
		Requirements: types.ResourceRequirements{CPU: "2"},
	}
	assert.InDelta(t, 0.10, EstimateCost(noMem, target, nil).Value, 0.0001)
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

// TestEstimateCost_PopulatesSelectedInstanceType verifies the estimate carries
// the selected instance type structurally (not just in the assumptions prose),
// so provisioning can launch the instance that was actually priced.
func TestEstimateCost_PopulatesSelectedInstanceType(t *testing.T) {
	cat, _, err := cloudvm.NewLiveCatalog(context.Background(), &stubFetcher{
		provider: cloudvm.ProviderHetzner,
		instances: []cloudvm.InstanceType{
			{Name: "cx22", Provider: cloudvm.ProviderHetzner, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.006, Arch: "x86_64"},
			{Name: "cx32", Provider: cloudvm.ProviderHetzner, VCPUs: 4, MemoryGB: 8, PricePerHour: 0.011, Arch: "x86_64"},
		},
	})
	require.NoError(t, err)

	// Requires 4 vCPU, so cx22 (2 vCPU) is infeasible and cx32 must be chosen.
	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Requirements: types.ResourceRequirements{CPU: "4"},
	}
	target := types.TargetConfig{
		Kind: types.TargetKindCloudVM,
		Capabilities: types.Capabilities{
			Accounting: types.AccountingCapability{RateCard: "hetzner"},
		},
	}

	est := EstimateCost(w, target, cat)
	assert.Equal(t, "cx32", est.InstanceType, "estimate must carry the priced instance type")
}

// TestRequirementsFromSpec_ThreadsGPUModel verifies an explicit GPU model pin
// reaches the catalog filter, so `model: h100` doesn't price/select a cheaper
// non-h100 GPU.
func TestRequirementsFromSpec_ThreadsGPUModel(t *testing.T) {
	spec := types.WorkloadSpec{
		Requirements: types.ResourceRequirements{
			GPU: types.GPURequirement{Required: true, Count: 1, Model: "h100"},
		},
	}

	req := requirementsFromSpec(spec)

	assert.Equal(t, "h100", req.GPUModel)
	assert.Equal(t, 1, req.GPUCount)
}

// An unpinned GPU leaves the model empty so the catalog returns the cheapest
// matching GPU instance.
func TestRequirementsFromSpec_NoModelLeavesGPUModelEmpty(t *testing.T) {
	spec := types.WorkloadSpec{
		Requirements: types.ResourceRequirements{
			GPU: types.GPURequirement{Required: true},
		},
	}

	req := requirementsFromSpec(spec)

	assert.Empty(t, req.GPUModel)
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

// TestEstimateCost_GPUResolutionMatrix pins the full GPU instance-resolution
// contract so the behavior can't silently regress: a GPU workload must resolve
// the same instance whether or not live pricing is available (only the price
// confidence differs), an unresolvable GPU must yield an empty InstanceType
// (which the run-time guard and plan-time risk key off), and model matching is
// case-insensitive. A nil catalog models the offline / DISABLE_LIVE_PRICING /
// no-creds path.
func TestEstimateCost_GPUResolutionMatrix(t *testing.T) {
	gpuSpec := func(model string) types.WorkloadSpec {
		return types.WorkloadSpec{
			DetectedKind: types.WorkloadKindGPUJob,
			Requirements: types.ResourceRequirements{
				GPU: types.GPURequirement{Required: true, Count: 1, Model: model},
			},
		}
	}
	cloudTarget := func(rateCard string) types.TargetConfig {
		return types.TargetConfig{
			Kind:         types.TargetKindCloudVM,
			Capabilities: types.Capabilities{Accounting: types.AccountingCapability{RateCard: rateCard}},
		}
	}

	cases := []struct {
		name         string
		model        string
		rateCard     string
		wantInstance string // "" means: must NOT resolve (run refuses, plan warns)
	}{
		// Offline (nil catalog) must still resolve a real GPU instance per provider.
		{"offline AWS any-GPU -> cheapest", "", "aws", "g4dn.xlarge"},
		{"offline AWS a10g", "a10g", "aws", "g5.xlarge"},
		{"offline GCP a100", "a100", "gcp", "a2-highgpu-1g"},
		{"offline Azure a100", "a100", "azure", "Standard_NC24ads_A100_v4"},
		// Case-insensitive model pin.
		{"offline AWS miscased T4", "T4", "aws", "g4dn.xlarge"},
		// Unresolvable -> empty (refuse): model exists nowhere.
		{"offline AWS unlisted h100 -> refuse", "h100", "aws", ""},
		// Unresolvable -> empty (refuse): Hetzner Cloud has no GPU SKU at all.
		{"offline Hetzner any-GPU -> refuse", "", "hetzner", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			est := EstimateCost(gpuSpec(tc.model), cloudTarget(tc.rateCard), nil)
			assert.Equal(t, tc.wantInstance, est.InstanceType)
		})
	}
}

// Hetzner Cloud has no GPU SKU (the gx11 catalog row was removed), so the rate
// card must not add a phantom GPU cost for a GPU workload that will be refused.
func TestEstimateCost_HetznerGPUHasNoPhantomCost(t *testing.T) {
	target := types.TargetConfig{
		Kind:         types.TargetKindCloudVM,
		Capabilities: types.Capabilities{Accounting: types.AccountingCapability{RateCard: "hetzner"}},
	}
	gpuSpec := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindScript,
		Requirements: types.ResourceRequirements{GPU: types.GPURequirement{Required: true, Count: 1}},
	}
	cpuSpec := types.WorkloadSpec{DetectedKind: types.WorkloadKindScript}

	gpu := EstimateCost(gpuSpec, target, nil)
	cpu := EstimateCost(cpuSpec, target, nil)

	assert.Equal(t, cpu.Value, gpu.Value, "Hetzner has no GPU SKU, so requiring a GPU must add no cost")
	assert.Empty(t, gpu.InstanceType, "and the GPU workload resolves no instance")
}

// Regression guard for the live-catalog-misses-provider -> static-fallback
// branch: when the live catalog lacks the target provider, a GPU instance is
// still resolved from the static catalog (instance only; price stays low-conf).
func TestEstimateCost_GPUResolvesFromStaticWhenLiveCatalogLacksProvider(t *testing.T) {
	cat, _, err := cloudvm.NewLiveCatalog(context.Background(), &stubFetcher{
		provider:  cloudvm.ProviderGCP,
		instances: []cloudvm.InstanceType{{Name: "e2-medium", Provider: cloudvm.ProviderGCP, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.034}},
	})
	require.NoError(t, err)

	gpuSpec := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindGPUJob,
		Requirements: types.ResourceRequirements{GPU: types.GPURequirement{Required: true, Count: 1}},
	}
	awsTarget := types.TargetConfig{
		Kind:         types.TargetKindCloudVM,
		Capabilities: types.Capabilities{Accounting: types.AccountingCapability{RateCard: "aws"}},
	}

	est := EstimateCost(gpuSpec, awsTarget, cat)
	assert.Equal(t, "g4dn.xlarge", est.InstanceType, "AWS GPU resolves from static when the live catalog lacks AWS")
	assert.Equal(t, types.ConfidenceLow, est.Confidence, "price stays low-confidence offline-style")
}
