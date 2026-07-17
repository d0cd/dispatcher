package cli

import (
	"context"
	"testing"

	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/stretchr/testify/assert"
)

func TestUsableLiveCatalog_PreservesPartialResultsAfterTimeout(t *testing.T) {
	cat, _, err := cloudvm.NewLiveCatalog(t.Context(), &pricingStubFetcher{})
	if err != nil {
		t.Fatal(err)
	}

	assert.Same(t, cat, usableLiveCatalog(cat, true),
		"a slow unrelated provider must not discard a successfully fetched catalog")
	assert.Nil(t, usableLiveCatalog(nil, true))
}

func TestScopedHetznerFetcherUsesRequestedRegion(t *testing.T) {
	fetcher := scopedHetznerFetcher("hetzner-vm", "hil")
	assert.Equal(t, "hil", fetcher.Location)

	unscoped := scopedHetznerFetcher("aws-vm", "us-west-2")
	assert.Empty(t, unscoped.Location, "a region from another provider must not be applied to Hetzner")
}

type pricingStubFetcher struct{}

func (*pricingStubFetcher) Provider() cloudvm.ProviderID { return cloudvm.ProviderHetzner }

func (*pricingStubFetcher) Fetch(_ context.Context) ([]cloudvm.InstanceType, error) {
	return []cloudvm.InstanceType{{
		Name: "cpx62", Provider: cloudvm.ProviderHetzner, VCPUs: 16,
		MemoryGB: 32, PricePerHour: 0.2452, Arch: "x86_64",
	}}, nil
}
