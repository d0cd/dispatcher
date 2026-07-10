package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// gc must flag ongoing cost that crosses the --warn-over threshold, so a leaked
// expensive resource can't sit unnoticed.
func TestGC_CostWarningOverThreshold(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false; gcFlags.warnOver = 10.0 })

	f := &fakeGCAdapter{
		id: "gcp-vm",
		resources: []adapter.ResourceInfo{{
			ResourceID: "leaked-gpu", Provider: "gcp", Kind: adapter.ResourceInstance,
			MonthlyUSD: 500, RunID: "run_gone",
			Tags: map[string]string{"dispatcher": "true", "dispatcher-run-id": "run_gone"},
		}},
	}
	withGCAdapter(t, f)

	stdout := captureStdout(t, func() {
		_, _, err := executeCommand("--output", "json", "gc", "--dry-run", "--warn-over", "100")
		require.NoError(t, err)
	})

	var r gcReport
	require.NoError(t, json.Unmarshal([]byte(stdout), &r))
	assert.InDelta(t, 500.0, r.MonthlyUSD, 0.01, "total ongoing cost is reported")
	assert.True(t, r.CostWarning, "cost over the threshold must set the warning flag")
}

func gcOrphanAdapter() *fakeGCAdapter {
	return &fakeGCAdapter{
		id:        "hetzner-vm",
		resources: []adapter.ResourceInfo{{ResourceID: "srv-1", Provider: "hetzner", RunID: "run_gone", Tags: map[string]string{"dispatcher": "true"}}},
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

// With zero orphans there is no destructive intent to disambiguate, so the
// --dry-run/--yes guard must not fire — a polling caller should get {found:0}.
func TestGC_JSON_NoOrphansEmitsEmptyReport(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := &fakeGCAdapter{id: "hetzner-vm"} // no resources → no orphans
	withGCAdapter(t, f)
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false })

	var runErr error
	out := captureStdout(t, func() { _, _, runErr = executeCommand("--output", "json", "gc") })
	require.NoError(t, runErr, "no orphans is not ambiguous intent; emit an empty report")

	var r gcReport
	require.NoError(t, json.Unmarshal([]byte(out), &r))
	assert.Equal(t, 0, r.Found)
	assert.Empty(t, f.destroyed)
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
