package cloudvm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalog_FindCheapest_Basic(t *testing.T) {
	cat := NewCatalog()
	results := cat.FindCheapest(InstanceRequirements{MinVCPUs: 2, MinMemoryGB: 4})

	require.NotEmpty(t, results)
	// Should be sorted by price
	for i := 1; i < len(results); i++ {
		assert.LessOrEqual(t, results[i-1].PricePerHour, results[i].PricePerHour)
	}
	// Cheapest should be Hetzner
	assert.Equal(t, ProviderHetzner, results[0].Provider)
}

func TestCatalog_FindCheapest_NonGPUExcludesGPUInstances(t *testing.T) {
	// A workload that needs no GPU must never be placed on (and billed for) a
	// GPU instance — even if one were cheaper — and GPU instances live in a
	// separate, often-zero quota bucket, so recommending one is unlaunchable.
	cat := NewCatalog()
	results := cat.FindCheapest(InstanceRequirements{})
	require.NotEmpty(t, results)
	for _, r := range results {
		assert.Zero(t, r.GPUCount, "non-GPU workload got a GPU instance: %s", r.Name)
	}
}

func TestCatalog_FindCheapest_GPU(t *testing.T) {
	cat := NewCatalog()
	results := cat.FindCheapest(InstanceRequirements{MinVCPUs: 4, GPUCount: 1})

	require.NotEmpty(t, results)
	for _, r := range results {
		assert.GreaterOrEqual(t, r.GPUCount, 1)
	}
}

func TestCatalog_FindCheapest_GPUModel(t *testing.T) {
	cat := NewCatalog()
	results := cat.FindCheapest(InstanceRequirements{GPUCount: 1, GPUModel: "a100"})

	require.NotEmpty(t, results)
	for _, r := range results {
		assert.Equal(t, "a100", r.GPUModel)
	}
}

// A user-pinned model like "A100" must match the lowercase catalog entry —
// otherwise a case mismatch silently yields no GPU instance.
func TestCatalog_FindCheapest_GPUModel_CaseInsensitive(t *testing.T) {
	cat := NewCatalog()
	results := cat.FindCheapest(InstanceRequirements{GPUCount: 1, GPUModel: "A100"})

	require.NotEmpty(t, results, "uppercase model pin should still match the catalog")
	for _, r := range results {
		assert.Equal(t, "a100", r.GPUModel)
	}
}

func TestCatalog_FindCheapest_ARM(t *testing.T) {
	cat := NewCatalog()
	results := cat.FindCheapest(InstanceRequirements{MinVCPUs: 4, Arch: "arm64"})

	require.NotEmpty(t, results)
	for _, r := range results {
		assert.Equal(t, "arm64", r.Arch)
	}
}

func TestCatalog_FindCheapest_NoMatch(t *testing.T) {
	cat := NewCatalog()
	results := cat.FindCheapest(InstanceRequirements{MinVCPUs: 1000})
	assert.Empty(t, results)
}

func TestCatalog_FindCheapestForProvider(t *testing.T) {
	cat := NewCatalog()
	results := cat.FindCheapestForProvider(ProviderHetzner, InstanceRequirements{MinVCPUs: 2, MinMemoryGB: 4})

	require.NotEmpty(t, results)
	for _, r := range results {
		assert.Equal(t, ProviderHetzner, r.Provider)
	}
}

func TestCatalog_Providers(t *testing.T) {
	cat := NewCatalog()
	providers := cat.Providers()

	assert.Contains(t, providers, ProviderHetzner)
	assert.Contains(t, providers, ProviderAWS)
	assert.Contains(t, providers, ProviderGCP)
	assert.Contains(t, providers, ProviderAzure)
}

func TestCatalog_HetznerCheapestOverall(t *testing.T) {
	cat := NewCatalog()
	// For basic 2 vCPU, 4GB workload, Hetzner should be cheapest
	results := cat.FindCheapest(InstanceRequirements{MinVCPUs: 2, MinMemoryGB: 4})
	require.NotEmpty(t, results)
	assert.Equal(t, ProviderHetzner, results[0].Provider)
}

func TestCatalog_CrossProviderGPUComparison(t *testing.T) {
	cat := NewCatalog()
	// T4 GPU comparison across providers
	results := cat.FindCheapest(InstanceRequirements{GPUCount: 1, GPUModel: "t4"})

	require.NotEmpty(t, results)
	// Verify we get T4 instances from multiple providers
	providers := map[ProviderID]bool{}
	for _, r := range results {
		providers[r.Provider] = true
	}
	assert.GreaterOrEqual(t, len(providers), 2, "T4 should be available from at least 2 providers")
}
