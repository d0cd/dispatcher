package confidential

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegistry_RoundTrip: a pin set + saved reloads identically, and the three
// clouds' measured images live in one registry (the single source of truth the
// adapters read and the build+capture flow writes).
func TestRegistry_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "confidential-pins.yaml")

	r := &Registry{}
	r.Set(AWSNitro, Pin{
		Image:       "/tmp/agent.eif",
		Measurement: "8410c2ae4dce6604",
		Extra:       map[string]string{"proxy": "/tmp/nitro-proxy"},
	})
	r.Set(AzureSNP, Pin{
		Image:       "/subscriptions/x/.../versions/2.0.0",
		Measurement: "815fba612c25c60d",
	})
	require.NoError(t, r.Save(path))

	got, err := Load(path)
	require.NoError(t, err)

	nitro, ok := got.Get(AWSNitro)
	require.True(t, ok)
	assert.Equal(t, "8410c2ae4dce6604", nitro.Measurement)
	assert.Equal(t, "/tmp/nitro-proxy", nitro.Extra["proxy"])

	az, ok := got.Get(AzureSNP)
	require.True(t, ok)
	assert.Equal(t, "815fba612c25c60d", az.Measurement)

	_, ok = got.Get(GCP)
	assert.False(t, ok, "an unset target has no pin")
}

// TestSave_AtomicAndPrivate: a saved registry is 0600 and leaves no temp file
// behind, so a crash mid-write can't surface a torn or world-readable registry.
func TestSave_AtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "confidential-pins.yaml")

	r := &Registry{}
	r.Set(GCP, Pin{Image: "ref@sha256:x", Measurement: "sha256:x"})
	require.NoError(t, r.Save(path))
	require.NoError(t, r.Save(path)) // overwrite an existing registry

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "registry is owner-only")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no leftover temp file")
	assert.Equal(t, "confidential-pins.yaml", entries[0].Name())
}

// TestLoad_MissingIsEmpty: a missing registry file loads as empty (not an error),
// so a fresh checkout works and the adapters fall back to env vars.
func TestLoad_MissingIsEmpty(t *testing.T) {
	r, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	require.NoError(t, err)
	_, ok := r.Get(GCP)
	assert.False(t, ok)
}

// TestSet_Overwrites: re-pinning a target replaces its measurement (build+capture
// re-writes the pin on every rebuild — measurements are content-addressed).
func TestSet_Overwrites(t *testing.T) {
	r := &Registry{}
	r.Set(GCP, Pin{Image: "ref@sha256:old", Measurement: "sha256:old"})
	r.Set(GCP, Pin{Image: "ref@sha256:new", Measurement: "sha256:new"})
	p, ok := r.Get(GCP)
	require.True(t, ok)
	assert.Equal(t, "sha256:new", p.Measurement)
}
