package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultPricingCacheTTL is how long a cached provider catalog stays fresh.
// Cloud on-demand prices change on the order of weeks, so a day turns the
// multi-second live fetch (GCP paginates ~30k SKUs; AWS makes ~8 CLI calls)
// into a once-per-day cost while keeping estimates accurate.
const DefaultPricingCacheTTL = 24 * time.Hour

// cachedFetcher wraps a Fetcher with an on-disk catalog cache keyed by provider
// and region. A fresh cache short-circuits the live fetch entirely; on a
// live-fetch failure it falls back to a stale cache when one exists, so a
// transient API outage doesn't silently drop the provider from the plan.
type cachedFetcher struct {
	inner  Fetcher
	region string
	dir    string
	ttl    time.Duration
	now    func() time.Time // test seam
}

// NewCachedFetcher wraps inner with a disk cache under dir. region distinguishes
// per-region catalogs for the same provider. A zero ttl uses
// DefaultPricingCacheTTL; an empty dir disables caching (always fetch live).
func NewCachedFetcher(inner Fetcher, region, dir string, ttl time.Duration) Fetcher {
	if ttl <= 0 {
		ttl = DefaultPricingCacheTTL
	}
	return &cachedFetcher{inner: inner, region: region, dir: dir, ttl: ttl, now: time.Now}
}

func (c *cachedFetcher) Provider() ProviderID { return c.inner.Provider() }

type pricingCacheFile struct {
	FetchedAt time.Time      `json:"fetchedAt"`
	Region    string         `json:"region"`
	Instances []InstanceType `json:"instances"`
}

func (c *cachedFetcher) path() string {
	region := c.region
	if region == "" {
		region = "default"
	}
	name := fmt.Sprintf("%s-%s.json", c.inner.Provider(), sanitizeCacheKey(region))
	return filepath.Join(c.dir, name)
}

func (c *cachedFetcher) Fetch(ctx context.Context) ([]InstanceType, error) {
	cached, cachedAt, ok := c.readCache()
	if ok && c.now().Sub(cachedAt) < c.ttl {
		return cached, nil
	}

	live, err := c.inner.Fetch(ctx)
	if err != nil {
		// Live fetch failed. A stale cache is better than dropping the provider,
		// so serve it if we have one; otherwise surface the error (so a genuine
		// creds/permission problem still shows up as skipped).
		if ok {
			return cached, nil
		}
		return nil, err
	}
	c.writeCache(live)
	return live, nil
}

func (c *cachedFetcher) readCache() ([]InstanceType, time.Time, bool) {
	if c.dir == "" {
		return nil, time.Time{}, false
	}
	b, err := os.ReadFile(c.path())
	if err != nil {
		return nil, time.Time{}, false
	}
	var f pricingCacheFile
	if err := json.Unmarshal(b, &f); err != nil || len(f.Instances) == 0 {
		return nil, time.Time{}, false
	}
	return f.Instances, f.FetchedAt, true
}

func (c *cachedFetcher) writeCache(instances []InstanceType) {
	// Never cache a non-answer: an empty fetch means "couldn't price", not
	// "this provider has no instances".
	if c.dir == "" || len(instances) == 0 {
		return
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return
	}
	b, err := json.Marshal(pricingCacheFile{FetchedAt: c.now().UTC(), Region: c.region, Instances: instances})
	if err != nil {
		return
	}
	// Best-effort, atomic via rename; a cache write failure must never break pricing.
	tmp := c.path() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, c.path())
	}
}

// sanitizeCacheKey keeps a region string safe as a filename component. Provider
// ids and region names are already [a-z0-9-], but guard against anything else.
func sanitizeCacheKey(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
