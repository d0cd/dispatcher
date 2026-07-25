package cloudvm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// gc estimates ongoing cost off the static rate card, which drifts most for GPU
// instances. RepriceInstancesLive overrides an instance's MonthlyUSD with the
// live catalog price when the catalog has it, leaving everything else untouched.
func TestRepriceInstancesLive(t *testing.T) {
	live := &Catalog{instances: []InstanceType{
		{Name: "g2-standard-4", Provider: ProviderGCP, PricePerHour: 0.85, GPUCount: 1},
	}}
	resources := []adapter.ResourceInfo{
		{Kind: adapter.ResourceInstance, Provider: "gcp", InstanceType: "g2-standard-4", MonthlyUSD: 0.700 * gcpMonthlyHours},
		{Kind: adapter.ResourceInstance, Provider: "gcp", InstanceType: "unknown-type", MonthlyUSD: 42},
		{Kind: adapter.ResourceDisk, Provider: "gcp", InstanceType: "g2-standard-4", MonthlyUSD: 5},
	}

	RepriceInstancesLive(resources, live)
	assert.InDelta(t, 0.85*gcpMonthlyHours, resources[0].MonthlyUSD, 1e-6, "GPU instance repriced from live catalog")
	assert.Equal(t, 42.0, resources[1].MonthlyUSD, "instance absent from live catalog stays static")
	assert.Equal(t, 5.0, resources[2].MonthlyUSD, "non-instance (disk) is never repriced")
}

// A nil live catalog (offline / live pricing disabled) leaves static estimates
// in place rather than zeroing them.
func TestRepriceInstancesLive_NilCatalogIsNoOp(t *testing.T) {
	resources := []adapter.ResourceInfo{
		{Kind: adapter.ResourceInstance, Provider: "gcp", InstanceType: "g2-standard-4", MonthlyUSD: 511},
	}
	RepriceInstancesLive(resources, nil)
	assert.Equal(t, 511.0, resources[0].MonthlyUSD)
}
