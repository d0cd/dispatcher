package cloudvm

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrCredentialsMissing is returned by a Fetcher when the provider's CLI is
// unauthenticated or the API key is absent. Callers treat this as "skip the
// provider" rather than a hard failure.
var ErrCredentialsMissing = errors.New("provider credentials not configured")

// Fetcher retrieves the current instance catalog (with prices) for one provider.
type Fetcher interface {
	Provider() ProviderID
	Fetch(ctx context.Context) ([]InstanceType, error)
}

// SkippedProvider records why a provider was excluded from a live fetch.
type SkippedProvider struct {
	Provider ProviderID
	Reason   string
}

// NewLiveCatalog calls every fetcher in parallel. Any provider that fails for
// any reason (missing creds, network error, rate limit, parse failure) is
// recorded in the skipped list and excluded from the catalog. Callers that
// want to fail loudly on transient errors should check the skipped list.
//
// This bias toward "skip and continue" is deliberate — when running `audit`
// or `plan`, partial pricing data is far more useful than no pricing data.
func NewLiveCatalog(ctx context.Context, fetchers ...Fetcher) (*Catalog, []SkippedProvider, error) {
	type result struct {
		provider  ProviderID
		instances []InstanceType
		skip      string
	}
	results := make([]result, len(fetchers))

	var wg sync.WaitGroup
	for i, f := range fetchers {
		wg.Add(1)
		go func(i int, f Fetcher) {
			defer wg.Done()
			instances, err := f.Fetch(ctx)
			r := result{provider: f.Provider()}
			switch {
			case errors.Is(err, ErrCredentialsMissing):
				r.skip = "no credentials configured"
			case err != nil:
				r.skip = fmt.Sprintf("transient: %s", truncateErr(err))
			case len(instances) == 0:
				// A fetch returning nothing (e.g. the AWS bulk list too large to
				// parse in time) is a non-answer, not "this provider has no
				// instances". Treating it as fetched would let seedStaticGPU
				// back-fill a GPU-only catalog.
				r.skip = "returned no instances"
			default:
				r.instances = instances
			}
			results[i] = r
		}(i, f)
	}
	wg.Wait()

	var (
		instances []InstanceType
		skipped   []SkippedProvider
		fetched   = map[ProviderID]bool{}
	)
	for _, r := range results {
		if r.skip != "" {
			skipped = append(skipped, SkippedProvider{Provider: r.provider, Reason: r.skip})
			continue
		}
		fetched[r.provider] = true
		instances = append(instances, r.instances...)
	}

	return &Catalog{instances: seedStaticGPU(instances, fetched)}, skipped, nil
}

// seedStaticGPU backfills GPU instances from the static catalog for any provider
// that was fetched live but whose feed returned no GPU rows (e.g. the Hetzner
// and Azure feeds carry no GPU SKUs). Without this, a GPU workload on such a
// provider resolves no instance type and is refused at provisioning even though
// the provider offers GPUs. Providers whose live feed already has GPU rows, or
// that were skipped entirely, are left untouched.
func seedStaticGPU(instances []InstanceType, fetched map[ProviderID]bool) []InstanceType {
	hasGPU := map[ProviderID]bool{}
	for _, inst := range instances {
		if inst.GPUCount > 0 {
			hasGPU[inst.Provider] = true
		}
	}
	for _, inst := range defaultInstances {
		if inst.GPUCount > 0 && fetched[inst.Provider] && !hasGPU[inst.Provider] {
			instances = append(instances, inst)
		}
	}
	return instances
}

// truncateErr keeps the skip reason short so a stack-trace-like error doesn't
// dominate the audit/plan output. 200 chars is enough to identify the
// failure mode (e.g. "azure retail prices status 429: ...") without spilling.
func truncateErr(err error) string {
	s := err.Error()
	const max = 200
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
