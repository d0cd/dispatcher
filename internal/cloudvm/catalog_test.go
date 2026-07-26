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

// Every GPU model a builtin target advertises must be served by a catalog
// instance for that provider, or the planner prices it off the rate card and
// mis-ranks it.
func TestCatalog_ServesAdvertisedGPUModels(t *testing.T) {
	cat := NewCatalog()
	cases := []struct {
		provider ProviderID
		model    string
	}{
		{ProviderAWS, "a100"}, {ProviderGCP, "h100"},
		{ProviderGCP, "a100"}, {ProviderAzure, "a100"},
	}
	for _, c := range cases {
		got := cat.FindCheapestForProvider(c.provider, InstanceRequirements{GPUCount: 1, GPUModel: c.model})
		assert.NotEmptyf(t, got, "%s must offer a %s instance in the catalog", c.provider, c.model)
	}
}

// TestFindCheapest_RejectsSpecLessRowForSizedRequest guards against a live price
// feed (e.g. Azure Retail Prices, which returns no per-SKU vCPU/memory) letting
// the globally cheapest spec-less SKU satisfy a request that pins a size. Picking
// it would under-provision the VM and under-report cost, silently passing a
// budget gate the correctly-sized VM would trip.
func TestFindCheapest_RejectsSpecLessRowForSizedRequest(t *testing.T) {
	cat := &Catalog{instances: []InstanceType{
		{Name: "Standard_B1ls", Provider: ProviderAzure, PricePerHour: 0.005, Arch: "x86_64"}, // spec-less, cheapest
		{Name: "Standard_D8s_v5", Provider: ProviderAzure, VCPUs: 8, MemoryGB: 32, PricePerHour: 0.384, Arch: "x86_64"},
	}}
	got := cat.FindCheapest(InstanceRequirements{MinVCPUs: 8, MinMemoryGB: 32})
	require.NotEmpty(t, got)
	assert.Equal(t, "Standard_D8s_v5", got[0].Name, "must pick the SKU that actually meets the size, not the cheapest spec-less row")
	for _, inst := range got {
		assert.NotEqual(t, "Standard_B1ls", inst.Name, "a spec-less row must not satisfy a sized request")
	}
}

// TestFindCheapest_KeepsSpecLessRowForUnsizedRequest confirms the guard only
// applies when a size is demanded: an unsized request still prices spec-less rows.
func TestFindCheapest_KeepsSpecLessRowForUnsizedRequest(t *testing.T) {
	cat := &Catalog{instances: []InstanceType{
		{Name: "Standard_B1ls", Provider: ProviderAzure, PricePerHour: 0.005, Arch: "x86_64"},
	}}
	got := cat.FindCheapest(InstanceRequirements{})
	require.Len(t, got, 1)
	assert.Equal(t, "Standard_B1ls", got[0].Name)
}

// TestEnrichSpecsFromStatic_FillsAzureLiveRowSpecs confirms a spec-less live row
// is enriched with the built-in table's vCPU/memory by SKU name while keeping the
// live price, so the size filters can select it.
func TestEnrichSpecsFromStatic_FillsAzureLiveRowSpecs(t *testing.T) {
	live := []InstanceType{
		{Name: "Standard_D8s_v5", Provider: ProviderAzure, PricePerHour: 0.30, Arch: "x86_64"}, // spec-less, live price
		{Name: "Standard_Unknown", Provider: ProviderAzure, PricePerHour: 0.01, Arch: "x86_64"},
	}
	got := enrichSpecsFromStatic(live)
	assert.Equal(t, 8, got[0].VCPUs, "vCPU filled from static table")
	assert.Equal(t, 32.0, got[0].MemoryGB, "memory filled from static table")
	assert.Equal(t, 0.30, got[0].PricePerHour, "live price preserved")
	assert.Equal(t, 0, got[1].VCPUs, "a SKU absent from the static table stays spec-less")
}
