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
	PricePerHour float64    `json:"pricePerHour"` // USD
	Arch         string     `json:"arch"`         // x86_64 or arm64
}

// InstanceRequirements describes what a workload needs.
type InstanceRequirements struct {
	MinVCPUs    int
	MinMemoryGB float64
	GPUCount    int
	GPUModel    string // "" means any
	Arch        string // "" means any
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
		// Some live price feeds (e.g. Azure's Retail Prices API) return a
		// price with no per-SKU specs. Skip the vCPU/memory filters when the
		// spec is unknown rather than rejecting the row — otherwise every
		// spec-less instance is silently discarded and the stale rate card is
		// used while we claim to be pricing live.
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
