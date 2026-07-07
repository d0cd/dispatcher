package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
)

func gcOrphanAdapter() *fakeGCAdapter {
	return &fakeGCAdapter{
		id:        "hetzner-vm",
		resources: []adapter.ResourceInfo{{ResourceID: "srv-1", Provider: "hetzner", RunID: "run_gone"}},
	}
}

func TestGC_JSON_DryRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := gcOrphanAdapter()
	withGCAdapter(t, f)
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false })

	var runErr error
	out := captureStdout(t, func() { _, _, runErr = executeCommand("--output", "json", "gc", "--dry-run") })
	require.NoError(t, runErr)

	var r gcReport
	require.NoError(t, json.Unmarshal([]byte(out), &r))
	assert.Equal(t, 1, r.Found)
	assert.Equal(t, 0, r.Destroyed)
	assert.True(t, r.DryRun)
	assert.Empty(t, f.destroyed, "dry-run destroys nothing")
}

func TestGC_JSON_Force(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := gcOrphanAdapter()
	withGCAdapter(t, f)
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false })

	var runErr error
	out := captureStdout(t, func() { _, _, runErr = executeCommand("--output", "json", "gc", "--yes") })
	require.NoError(t, runErr)

	var r gcReport
	require.NoError(t, json.Unmarshal([]byte(out), &r))
	assert.Equal(t, 1, r.Found)
	assert.Equal(t, 1, r.Destroyed)
	require.Len(t, r.Orphans, 1)
	assert.True(t, r.Orphans[0].Destroyed)
	assert.Equal(t, []string{"srv-1"}, f.destroyed)
}

func TestGC_JSON_RequiresDryRunOrForce(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := gcOrphanAdapter()
	withGCAdapter(t, f)
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false })

	// --json can't prompt, so refuse to guess intent — never destroy silently.
	_, _, err := executeCommand("--output", "json", "gc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dry-run")
	assert.Empty(t, f.destroyed, "nothing destroyed when the intent is ambiguous")
}
