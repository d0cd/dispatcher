package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/types"
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

// A cloud VM is tagged with the PLAN id (the adapter never sees the run id), so
// gc must protect it while its run is still active — keying the guard on the run
// id can never match the plan-id tag and would reap live VMs.
func TestGC_DoesNotReapActiveRunTaggedWithPlanID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false })

	p := &types.Plan{
		Metadata:       types.PlanMetadata{ID: "plan_active"},
		Recommendation: &types.Recommendation{Target: "hetzner-vm"},
	}
	r := run.NewRun(p)
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning)) // non-terminal → active
	_, err := r.Save()
	require.NoError(t, err)

	f := &fakeGCAdapter{
		id: "hetzner-vm",
		resources: []adapter.ResourceInfo{{
			ResourceID: "srv-live", Provider: "hetzner", RunID: p.Metadata.ID,
			Tags: map[string]string{"dispatcher": "true", "dispatcher-run-id": p.Metadata.ID},
		}},
	}
	withGCAdapter(t, f)

	var runErr error
	out := captureStdout(t, func() { _, _, runErr = executeCommand("--output", "json", "gc", "--dry-run") })
	require.NoError(t, runErr)

	var report gcReport
	require.NoError(t, json.Unmarshal([]byte(out), &report))
	assert.Equal(t, 0, report.Found, "a VM whose run is still active must not be an orphan")
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
	out := captureStdout(t, func() { _, _, runErr = executeCommand("--output", "json", "gc", "--yes", "--allow-empty-store") })
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

// A corrupt run record whose plan id is still recoverable must protect its VM
// (the record could belong to a live run) — gc recovers the plan id from the raw
// file rather than reaping the resource.
func TestGC_ProtectsCorruptRecordVMByRecoveredPlanID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false })

	dir, err := run.StoreDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	// Truncated record (crash mid-write) — unparseable, but planId is recoverable.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "run_corrupt.json"),
		[]byte(`{"id":"run_corrupt","planId":"plan_corrupt","state":"run`), 0o600))

	f := &fakeGCAdapter{
		id: "hetzner-vm",
		resources: []adapter.ResourceInfo{{
			ResourceID: "srv-corrupt", Provider: "hetzner", RunID: "plan_corrupt",
			Tags: map[string]string{"dispatcher": "true", "dispatcher-run-id": "plan_corrupt"},
		}},
	}
	withGCAdapter(t, f)

	var runErr error
	out := captureStdout(t, func() { _, _, runErr = executeCommand("--output", "json", "gc", "--dry-run") })
	require.NoError(t, runErr)
	var report gcReport
	require.NoError(t, json.Unmarshal([]byte(out), &report))
	assert.Equal(t, 0, report.Found, "a corrupt record's VM must be protected, not reaped")
}

// Every provisionable cloud-VM target must be discoverable by gc, or an orphaned
// VM of that provider bills forever and never appears in `dispatcher gc`.
func TestGCDiscoversAllCloudTargets(t *testing.T) {
	for _, target := range []string{"hetzner-vm", "aws-vm", "gcp-vm", "azure-vm", "oci-vm", "lambda-vm"} {
		_, viaCLI := gcProviderCLIs[target]
		_, viaEnv := gcProviderEnv[target]
		assert.True(t, viaCLI || viaEnv, "gc must discover %s (it's a provisionable target) or it leaks orphaned VMs invisibly", target)
	}
}

// gc scans Azure subscription-wide and every accessible GCP project; the note
// states each cloud's residual boundary (other subscriptions; unlistable projects).
func TestScopeLimitNote(t *testing.T) {
	n := scopeLimitNote([]string{"hetzner-vm", "azure-vm", "gcp-vm", "aws-vm"})
	assert.Contains(t, n, "Azure")
	assert.Contains(t, n, "subscription")
	assert.Contains(t, n, "GCP")
	assert.Contains(t, n, "project")

	az := scopeLimitNote([]string{"azure-vm"})
	assert.Contains(t, az, "Azure")
	assert.NotContains(t, az, "GCP (")

	// Neither cloud present → no note.
	assert.Empty(t, scopeLimitNote([]string{"hetzner-vm", "aws-vm"}))
}
