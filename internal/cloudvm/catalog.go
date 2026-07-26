package cloudvm

import (
	"sort"
	"strings"
)

// InstanceType describes a single VM offering with pricing.
type InstanceType struct {
	Name         string     `json:"name"`
	Provider     ProviderID `json:"provider"`
	VCPUs        int        `json:"vcpus"`
	MemoryGB     float64    `json:"memoryGb"`
	GPUCount     int        `json:"gpuCount,omitempty"`
	GPUModel     string     `json:"gpuModel,omitempty"`
	PricePerHour float64    `json:"pricePerHour"` // USD, on-demand
	// SpotPricePerHour is the live spot/preemptible hourly price when the fetcher
	// can source it (GCP preemptible SKUs, AWS spot-price-history). 0 = unknown,
	// in which case the estimator falls back to a per-provider discount factor.
	SpotPricePerHour float64 `json:"spotPricePerHour,omitempty"`
	Arch             string  `json:"arch"` // x86_64 or arm64
	// Confidential marks a memory-encrypted (SEV-SNP / TDX) SKU. These are a
	// separate, pricier bucket: a confidential workload must be priced on one,
	// and a plain workload must never be.
	Confidential bool `json:"confidential,omitempty"`
}

// InstanceRequirements describes what a workload needs.
type InstanceRequirements struct {
	MinVCPUs    int
	MinMemoryGB float64
	GPUCount    int
	GPUModel    string // "" means any
	Arch        string // "" means any
	// Confidential requires a memory-encrypted SKU (and excludes one otherwise),
	// so the estimate matches the CVM SKU the provider actually launches.
	Confidential bool
}

// Catalog holds instance types across providers.
type Catalog struct {
	instances []InstanceType
}

// NewCatalog creates a catalog from the built-in instance data.
func NewCatalog() *Catalog {
	return &Catalog{instances: defaultInstances}
}

// FindCheapest returns instances matching requirements, sorted by price ascending.
func (c *Catalog) FindCheapest(req InstanceRequirements) []InstanceType {
	var matches []InstanceType
	for _, inst := range c.instances {
		// Some live price feeds (e.g. Azure's Retail Prices API) return a price
		// with no per-SKU specs; enrichSpecsFromStatic backfills specs for SKUs in
		// the built-in table. A row still spec-less here cannot satisfy a request
		// that pins a size: matching it would let the globally cheapest spec-less
		// SKU under-provision the VM and under-report cost (silently passing a
		// budget gate a right-sized VM would trip). When no size is required an
		// unknown-spec row is still eligible, so the live rate card is not discarded.
		if req.MinVCPUs > 0 && inst.VCPUs == 0 {
			continue
		}
		if req.MinMemoryGB > 0 && inst.MemoryGB == 0 {
			continue
		}
		if inst.VCPUs > 0 && inst.VCPUs < req.MinVCPUs {
			continue
		}
		if inst.MemoryGB > 0 && inst.MemoryGB < req.MinMemoryGB {
			continue
		}
		if req.GPUCount > 0 && inst.GPUCount < req.GPUCount {
			continue
		}
		// A non-GPU workload must never land on a GPU instance: it wastes money,
		// and GPU instances sit in a separate (often zero) quota bucket, so the
		// recommendation would be unlaunchable.
		if req.GPUCount == 0 && inst.GPUCount > 0 {
			continue
		}
		if req.GPUModel != "" && !strings.EqualFold(inst.GPUModel, req.GPUModel) {
			continue
		}
		// Confidential SKUs are a separate bucket: only a confidential requirement
		// may match them, and it may match nothing else — otherwise a plain run is
		// priced on a CVM, or a confidential run is under-priced on a plain SKU.
		if req.Confidential != inst.Confidential {
			continue
		}
		if req.Arch != "" && inst.Arch != req.Arch {
			continue
		}
		matches = append(matches, inst)
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].PricePerHour < matches[j].PricePerHour
	})

	return matches
}

// PriceByName returns the hourly USD price for a named instance type of a
// provider, or 0 if the catalog doesn't know it.
func (c *Catalog) PriceByName(provider ProviderID, name string) float64 {
	for _, inst := range c.instances {
		if inst.Provider == provider && inst.Name == name {
			return inst.PricePerHour
		}
	}
	return 0
}

// FindCheapestForProvider filters to a single provider.
func (c *Catalog) FindCheapestForProvider(provider ProviderID, req InstanceRequirements) []InstanceType {
	all := c.FindCheapest(req)
	var filtered []InstanceType
	for _, inst := range all {
		if inst.Provider == provider {
			filtered = append(filtered, inst)
		}
	}
	return filtered
}

// Providers returns the set of providers in the catalog.
func (c *Catalog) Providers() []ProviderID {
	seen := map[ProviderID]bool{}
	var providers []ProviderID
	for _, inst := range c.instances {
		if !seen[inst.Provider] {
			seen[inst.Provider] = true
			providers = append(providers, inst.Provider)
		}
	}
	return providers
}
