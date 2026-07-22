package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"

	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/state"
)

// loadLiveCatalog runs every configured provider's pricing fetcher in parallel
// and returns the merged catalog plus any providers that were skipped because
// credentials are missing. The caller is expected to surface skipped providers
// to the user (they'll be absent from cost comparisons).
//
// A 30-second timeout caps the wait so a hung provider can't stall the whole
// plan command.
//
// Set DISPATCHER_DISABLE_LIVE_PRICING=1 to bypass the live fetch entirely.
// Used by tests so the suite isn't gated on real outbound network calls.
func loadLiveCatalog(stderr io.Writer) *cloudvm.Catalog {
	return loadLiveCatalogScoped(stderr, "", "")
}

// loadLiveCatalogScoped pins a provider fetch to the region that the run will
// actually use. A globally cheap SKU may be unavailable there; pricing it and
// then provisioning in another region is both incorrect and unlaunchable.
func loadLiveCatalogScoped(stderr io.Writer, targetID, region string) *cloudvm.Catalog {
	if os.Getenv("DISPATCHER_DISABLE_LIVE_PRICING") != "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Every fetcher is wrapped in a disk cache (keyed by the region it prices) so
	// the multi-second live fetches — GCP paginates ~30k SKUs, AWS makes ~8 CLI
	// calls — become a once-per-day cost, and a transient API outage falls back
	// to the last good prices instead of dropping the provider.
	cacheDir, cacheTTL := pricingCache()
	cache := func(f cloudvm.Fetcher, r string) cloudvm.Fetcher {
		return cloudvm.NewCachedFetcher(f, r, cacheDir, cacheTTL)
	}
	fetchers := []cloudvm.Fetcher{
		cache(scopedHetznerFetcher(targetID, region), regionFor("hetzner-vm", targetID, region)),
		cache(cloudvm.NewAzureFetcher(""), ""),
		cache(cloudvm.NewGCPFetcher(""), ""),
		cache(scopedLambdaFetcher(targetID, region), regionFor("lambda-vm", targetID, region)),
	}
	// AWS live pricing (the Price List Query API) is ~8 sequential CLI calls.
	// Fetch it when AWS is the target or when comparing all clouds (targetID
	// empty); skip it for a specific non-AWS target, which keeps the fast
	// rate-card AWS estimate it always used. (AWS bulk pricing never resolved in
	// time, so this is no regression — and the fetch runs concurrently with the
	// other providers, so it adds little wall time.)
	if targetID == "aws-vm" || targetID == "" {
		fetchers = append(fetchers, cache(cloudvm.NewAWSFetcher(region), region))
	}

	cat, skipped, err := cloudvm.NewLiveCatalog(ctx, fetchers...)
	if err != nil {
		dim := color.New(color.Faint)
		dim.Fprintf(stderr, "Live pricing unavailable: %v\n", err)
		dim.Fprintln(stderr, "Falling back to built-in estimates (confidence: low).")
		return nil
	}
	if ctx.Err() != nil && usableLiveCatalog(cat, true) == nil {
		// All fetchers were skipped via timeout. NewLiveCatalog returned an
		// empty catalog rather than an error, but we shouldn't pretend the
		// estimates are live.
		dim := color.New(color.Faint)
		dim.Fprintln(stderr, "Live pricing fetch timed out. Falling back to built-in estimates (confidence: low).")
		return nil
	}
	if ctx.Err() != nil {
		dim := color.New(color.Faint)
		dim.Fprintln(stderr, "Some live pricing fetches timed out; using the providers that completed.")
	}

	if len(skipped) > 0 {
		dim := color.New(color.Faint)
		for _, s := range skipped {
			dim.Fprintf(stderr, "Skipped %s pricing: %s\n", s.Provider, s.Reason)
		}
	}

	return cat
}

// pricingCache resolves the on-disk pricing-cache directory and TTL. An empty
// dir disables caching (fetch live every time). DISPATCHER_PRICING_CACHE_TTL
// overrides the default: a positive duration (e.g. "6h") shortens it, and "0"
// or a non-positive value disables the cache.
func pricingCache() (string, time.Duration) {
	ttl := cloudvm.DefaultPricingCacheTTL
	if v := os.Getenv("DISPATCHER_PRICING_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			if d <= 0 {
				return "", 0
			}
			ttl = d
		}
	}
	dir, err := state.Dir()
	if err != nil {
		return "", ttl
	}
	return filepath.Join(dir, "pricing-cache"), ttl
}

// regionFor returns the run region for the fetcher that scopes to self, else ""
// (providers that always price their default region). It mirrors the scoping in
// scopedHetznerFetcher/scopedLambdaFetcher so the cache key matches the priced region.
func regionFor(self, targetID, region string) string {
	if targetID == self {
		return region
	}
	return ""
}

func scopedHetznerFetcher(targetID, region string) *cloudvm.HetznerFetcher {
	fetcher := cloudvm.NewHetznerFetcher()
	if targetID == "hetzner-vm" {
		fetcher.Location = region
	}
	return fetcher
}

// scopedLambdaFetcher pins the Lambda capacity filter to the run's region only
// when lambda-vm is the target; otherwise it prices every type with capacity
// anywhere (so it can appear as an alternative). Self-skips without an API key.
func scopedLambdaFetcher(targetID, region string) *cloudvm.LambdaFetcher {
	r := ""
	if targetID == "lambda-vm" {
		r = region
	}
	return cloudvm.NewLambdaFetcher(r)
}

func usableLiveCatalog(cat *cloudvm.Catalog, timedOut bool) *cloudvm.Catalog {
	if !timedOut {
		return cat
	}
	if cat == nil || len(cat.Providers()) == 0 {
		return nil
	}
	return cat
}

// formatPricingFootnote returns a short footer summarizing how pricing was
// sourced. Empty when there's nothing useful to say.
func formatPricingFootnote(cat *cloudvm.Catalog) string {
	if cat == nil {
		return "pricing: offline (using built-in estimates)"
	}
	providers := cat.Providers()
	if len(providers) == 0 {
		return ""
	}
	return fmt.Sprintf("pricing: live from %v", providers)
}
