package cloudvm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubFetcher is a Fetcher whose Fetch returns a configurable result and counts
// calls, so cache tests can assert whether the live fetch was invoked.
type stubFetcher struct {
	provider  ProviderID
	instances []InstanceType
	err       error
	calls     int
}

func (s *stubFetcher) Provider() ProviderID { return s.provider }
func (s *stubFetcher) Fetch(_ context.Context) ([]InstanceType, error) {
	s.calls++
	return s.instances, s.err
}

func sampleInstances() []InstanceType {
	return []InstanceType{{Name: "t3.micro", Provider: ProviderAWS, VCPUs: 2, MemoryGB: 1, PricePerHour: 0.0104}}
}

func TestCachedFetcher_FreshCacheSkipsLiveFetch(t *testing.T) {
	dir := t.TempDir()
	inner := &stubFetcher{provider: ProviderAWS, instances: sampleInstances()}
	c := &cachedFetcher{inner: inner, region: "us-east-1", dir: dir, ttl: time.Hour, now: time.Now}

	first, err := c.Fetch(context.Background())
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.Equal(t, 1, inner.calls, "first fetch goes live")

	// A second fetcher over the same dir must hit the cache, not the inner fetch.
	inner2 := &stubFetcher{provider: ProviderAWS, instances: sampleInstances()}
	c2 := &cachedFetcher{inner: inner2, region: "us-east-1", dir: dir, ttl: time.Hour, now: time.Now}
	second, err := c2.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, first, second)
	assert.Equal(t, 0, inner2.calls, "fresh cache must not invoke the live fetch")
}

func TestCachedFetcher_ExpiredCacheRefetches(t *testing.T) {
	dir := t.TempDir()
	base := time.Unix(1_000_000, 0).UTC()
	inner := &stubFetcher{provider: ProviderAWS, instances: sampleInstances()}
	clock := base
	c := &cachedFetcher{inner: inner, region: "r", dir: dir, ttl: time.Hour, now: func() time.Time { return clock }}

	_, err := c.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, inner.calls)

	clock = base.Add(2 * time.Hour) // past the TTL
	_, err = c.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, inner.calls, "an expired cache must re-fetch")
}

func TestCachedFetcher_ServesStaleOnFetchError(t *testing.T) {
	dir := t.TempDir()
	base := time.Unix(2_000_000, 0).UTC()
	clock := base

	// Seed a cache with a successful fetch.
	seed := &stubFetcher{provider: ProviderAWS, instances: sampleInstances()}
	c := &cachedFetcher{inner: seed, region: "r", dir: dir, ttl: time.Hour, now: func() time.Time { return clock }}
	_, err := c.Fetch(context.Background())
	require.NoError(t, err)

	// Now the cache is stale AND the live fetch fails — serve the stale data.
	clock = base.Add(48 * time.Hour)
	failing := &stubFetcher{provider: ProviderAWS, err: errors.New("api down")}
	c2 := &cachedFetcher{inner: failing, region: "r", dir: dir, ttl: time.Hour, now: func() time.Time { return clock }}
	got, err := c2.Fetch(context.Background())
	require.NoError(t, err, "a failed live fetch with a stale cache must not error")
	require.Len(t, got, 1)
	assert.Equal(t, 1, failing.calls)
}

// A permanent creds/permission failure must surface (so the provider shows as
// skipped) even when a stale cache exists — stale-on-failure is for transient
// outages, not for masking a removed credential.
func TestCachedFetcher_MissingCredsNotMaskedByStaleCache(t *testing.T) {
	dir := t.TempDir()
	base := time.Unix(3_000_000, 0).UTC()
	clock := base
	seed := &stubFetcher{provider: ProviderAWS, instances: sampleInstances()}
	c := &cachedFetcher{inner: seed, region: "r", dir: dir, ttl: time.Hour, now: func() time.Time { return clock }}
	_, err := c.Fetch(context.Background())
	require.NoError(t, err)

	clock = base.Add(48 * time.Hour) // stale
	creds := &stubFetcher{provider: ProviderAWS, err: ErrCredentialsMissing}
	c2 := &cachedFetcher{inner: creds, region: "r", dir: dir, ttl: time.Hour, now: func() time.Time { return clock }}
	_, err = c2.Fetch(context.Background())
	assert.ErrorIs(t, err, ErrCredentialsMissing, "missing creds must not be masked by a stale cache")
}

func TestCachedFetcher_FetchErrorNoCachePropagates(t *testing.T) {
	inner := &stubFetcher{provider: ProviderAWS, err: ErrCredentialsMissing}
	c := &cachedFetcher{inner: inner, region: "r", dir: t.TempDir(), ttl: time.Hour, now: time.Now}
	_, err := c.Fetch(context.Background())
	assert.ErrorIs(t, err, ErrCredentialsMissing, "no cache + failed fetch surfaces the error")
}

func TestCachedFetcher_EmptyResultNotCached(t *testing.T) {
	dir := t.TempDir()
	// An empty fetch is a non-answer, so it must not be written as a cache hit.
	inner := &stubFetcher{provider: ProviderAWS, instances: nil}
	c := &cachedFetcher{inner: inner, region: "r", dir: dir, ttl: time.Hour, now: time.Now}
	_, err := c.Fetch(context.Background())
	require.NoError(t, err)

	inner2 := &stubFetcher{provider: ProviderAWS, instances: sampleInstances()}
	c2 := &cachedFetcher{inner: inner2, region: "r", dir: dir, ttl: time.Hour, now: time.Now}
	_, err = c2.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, inner2.calls, "an empty result must not be cached")
}
