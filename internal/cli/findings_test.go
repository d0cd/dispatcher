package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/approval"
	"github.com/d0cd/dispatcher/internal/run"
	statedir "github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/target"
	"github.com/d0cd/dispatcher/internal/types"
)

// ---- P4: parseOptimize ----

func TestParseOptimize(t *testing.T) {
	cost, err := parseOptimize("cost")
	require.NoError(t, err)
	assert.Equal(t, types.OptimizeCost, cost)

	speed, err := parseOptimize("speed")
	require.NoError(t, err)
	assert.Equal(t, types.OptimizeSpeed, speed)

	_, err = parseOptimize("spd")
	assert.Error(t, err)

	_, err = parseOptimize("")
	assert.Error(t, err)
}

// ---- P1: targets add SSH flags + adapterForTarget ----

func TestTargetsAddSSHPopulatesConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	addFlags.host = ""
	addFlags.user = ""
	addFlags.port = 22
	addFlags.enabled = true

	_, _, err := executeCommand("targets", "add", "ssh-box",
		"--kind", "ssh", "--host", "example.com", "--user", "deploy", "--port", "2222")
	require.NoError(t, err)

	reg := target.NewRegistry()
	require.NoError(t, reg.LoadUserConfig())
	tc, ok := reg.Get("ssh-box")
	require.True(t, ok)
	require.NotNil(t, tc.SSH)
	assert.Equal(t, "example.com", tc.SSH.Host)
	assert.Equal(t, "deploy", tc.SSH.User)
	assert.Equal(t, 2222, tc.SSH.Port)
}

func TestTargetsAddSSHRequiresHost(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	addFlags.host = ""
	addFlags.user = ""
	addFlags.port = 22
	addFlags.enabled = true

	_, _, err := executeCommand("targets", "add", "no-host", "--kind", "ssh")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires --host")
}

func TestAdapterForTargetSSHNoHostErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, err := target.SaveTarget(types.TargetConfig{
		ID:      "broken-ssh",
		Kind:    types.TargetKindSSH,
		Enabled: true,
		SSH:     nil,
	})
	require.NoError(t, err)

	_, err = adapterForTarget("broken-ssh")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken-ssh")
	assert.NotContains(t, err.Error(), "localhost")
}

// ---- P3: stop --force ----

func TestStopForceFinalizesStrandedRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stopFlags.force = false

	rec := &run.RunRecord{
		ID:       "run_stranded01",
		TargetID: "hetzner-vm",
		State:    types.RunStateRunning, // non-terminal, no HandleState
	}
	r := run.RunFromRecord(rec)
	_, err := r.Save()
	require.NoError(t, err)

	// Without --force the stranded record can't be reconnected → error, still non-terminal.
	_, _, err = executeCommand("stop", "run_stranded01")
	assert.Error(t, err)
	reloaded, err := run.LoadRecord("run_stranded01")
	require.NoError(t, err)
	assert.False(t, reloaded.State.IsTerminal(), "without --force the record should remain non-terminal")

	// With --force it finalizes.
	stopFlags.force = false
	_, _, err = executeCommand("stop", "run_stranded01", "--force")
	require.NoError(t, err)
	reloaded, err = run.LoadRecord("run_stranded01")
	require.NoError(t, err)
	assert.True(t, reloaded.State.IsTerminal(), "with --force the record should be terminal")
	assert.NotEmpty(t, reloaded.Error)
}

// ---- P7: non-TTY approval hint ----

func TestTerminalApprovalNonTTYHints(t *testing.T) {
	rOld, wOld := os.Stdin, os.Stderr
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	pw.Close() // EOF on read
	os.Stdin = pr

	errR, errW, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = errW

	defer func() {
		os.Stdin = rOld
		os.Stderr = wOld
	}()

	decider, derr := terminalApproval([]types.PolicyRequirement{{Name: "deploy", Reason: "prod"}})
	errW.Close()
	captured, _ := io.ReadAll(errR)
	pr.Close()

	assert.NotEmpty(t, decider)
	require.ErrorIs(t, derr, approval.ErrDenied)
	assert.Contains(t, string(captured), "--yes")
	assert.Contains(t, string(captured), "dispatcher approve")
}

// ---- P8: --no-color / --state-dir global flags ----

func TestNoColorFlag(t *testing.T) {
	prev := color.NoColor
	t.Cleanup(func() { color.NoColor = prev })
	t.Setenv("HOME", t.TempDir())

	_, _, err := executeCommand("--no-color", "list")
	require.NoError(t, err)
	assert.True(t, color.NoColor)
}

func TestStateDirFlag(t *testing.T) {
	prev := os.Getenv("DISPATCHER_HOME")
	t.Cleanup(func() { os.Setenv("DISPATCHER_HOME", prev) })

	tmp := t.TempDir()
	_, _, err := executeCommand("--state-dir", tmp, "list")
	require.NoError(t, err)
	assert.Equal(t, tmp, os.Getenv("DISPATCHER_HOME"))
}

// ---- P9: checkSSH ----

func TestCheckSSH_NoHostSkips(t *testing.T) {
	c := checkSSH(context.Background(), types.TargetConfig{Kind: types.TargetKindSSH})
	assert.Equal(t, "skip", c.status)
}

func TestCheckSSH_UnreachableHostFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := checkSSH(ctx, types.TargetConfig{
		Kind: types.TargetKindSSH,
		SSH:  &types.SSHTargetConfig{Host: "192.0.2.1", User: "nobody"},
	})
	assert.Equal(t, "fail", c.status)
}

// ---- S3: gc confirmation ----

type fakeGCAdapter struct {
	id         string
	resources  []adapter.ResourceInfo
	destroyed  []string
	destroyErr map[string]error // per-resource-id destroy failure
	listErr    error            // ListResources failure
}

func (f *fakeGCAdapter) ID() string { return f.id }
func (f *fakeGCAdapter) Validate(context.Context, types.WorkloadSpec) (types.ValidationResult, error) {
	return types.ValidationResult{}, nil
}
func (f *fakeGCAdapter) EstimateCost(context.Context, types.WorkloadSpec) (types.CostEstimate, error) {
	return types.CostEstimate{}, nil
}
func (f *fakeGCAdapter) Prepare(context.Context, *types.Plan) error { return nil }
func (f *fakeGCAdapter) Execute(context.Context, *types.Plan) (*adapter.RunHandle, error) {
	return nil, nil
}
func (f *fakeGCAdapter) Status(context.Context, *adapter.RunHandle) (types.RunState, error) {
	return types.RunStateRunning, nil
}
func (f *fakeGCAdapter) Logs(context.Context, *adapter.RunHandle, io.Writer) error { return nil }
func (f *fakeGCAdapter) Artifacts(context.Context, *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
	return nil, nil
}
func (f *fakeGCAdapter) Terminate(context.Context, *adapter.RunHandle) error { return nil }
func (f *fakeGCAdapter) Cleanup(context.Context, *adapter.RunHandle) (*adapter.CleanupResult, error) {
	return &adapter.CleanupResult{Success: true}, nil
}
func (f *fakeGCAdapter) Reconnect(context.Context, string, json.RawMessage) (*adapter.RunHandle, error) {
	return nil, nil
}
func (f *fakeGCAdapter) ExtendWatchdog(context.Context, *adapter.RunHandle, time.Duration) (time.Time, error) {
	return time.Time{}, nil
}
func (f *fakeGCAdapter) ListResources(context.Context) ([]adapter.ResourceInfo, error) {
	return f.resources, f.listErr
}
func (f *fakeGCAdapter) DestroyResource(_ context.Context, res adapter.ResourceInfo) error {
	if err := f.destroyErr[res.ResourceID]; err != nil {
		return err // a failed destroy must NOT be recorded as destroyed
	}
	f.destroyed = append(f.destroyed, res.ResourceID)
	return nil
}

func withGCAdapter(t *testing.T, f *fakeGCAdapter) {
	t.Helper()
	prev := durableAdaptersFn
	durableAdaptersFn = func() []adapter.DurableAdapter {
		return []adapter.DurableAdapter{f}
	}
	t.Cleanup(func() { durableAdaptersFn = prev })
}

func withStdin(t *testing.T, content string) {
	t.Helper()
	prev := os.Stdin
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	go func() {
		pw.WriteString(content)
		pw.Close()
	}()
	os.Stdin = pr
	t.Cleanup(func() {
		os.Stdin = prev
		pr.Close()
	})
}

func orphanFixture() *fakeGCAdapter {
	return &fakeGCAdapter{
		id: "hetzner-vm",
		resources: []adapter.ResourceInfo{
			{ResourceID: "srv-123", Provider: "hetzner", RunID: "run_gone", Tags: map[string]string{"dispatcher": "true"}},
		},
	}
}

func TestGC_NoConfirmDoesNotDestroy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	f := orphanFixture()
	withGCAdapter(t, f)
	withStdin(t, "n\n")

	_, _, err := executeCommand("gc", "--allow-empty-store")
	require.NoError(t, err)
	assert.Empty(t, f.destroyed, "declining the prompt must not destroy anything")
}

func TestGC_EmptyInputDoesNotDestroy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	f := orphanFixture()
	withGCAdapter(t, f)
	withStdin(t, "\n")

	_, _, err := executeCommand("gc", "--allow-empty-store")
	require.NoError(t, err)
	assert.Empty(t, f.destroyed)
}

func TestGC_YesConfirmDestroys(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	f := orphanFixture()
	withGCAdapter(t, f)
	withStdin(t, "y\n")

	_, _, err := executeCommand("gc", "--allow-empty-store")
	require.NoError(t, err)
	assert.Equal(t, []string{"srv-123"}, f.destroyed)
}

func TestGC_YesFlagDestroysWithoutPrompt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	f := orphanFixture()
	withGCAdapter(t, f)

	_, _, err := executeCommand("gc", "--yes", "--allow-empty-store")
	require.NoError(t, err)
	assert.Equal(t, []string{"srv-123"}, f.destroyed)
}

func TestGC_ReclaimsPerRunSSHKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false

	keyDir, err := statedir.Subdir("keys")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(keyDir, 0o700))
	keyPath := keyDir + "/dispatcher-run_gone" // orphanFixture's RunID
	require.NoError(t, os.WriteFile(keyPath, []byte("k"), 0o600))

	f := orphanFixture()
	withGCAdapter(t, f)

	_, _, err = executeCommand("gc", "--yes", "--allow-empty-store")
	require.NoError(t, err)
	require.Equal(t, []string{"srv-123"}, f.destroyed)

	_, statErr := os.Stat(keyPath)
	assert.True(t, os.IsNotExist(statErr), "gc must reclaim the per-run SSH key after destroying the VM")
}

func TestGC_DryRunNeverDestroys(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	f := orphanFixture()
	withGCAdapter(t, f)

	_, _, err := executeCommand("gc", "--dry-run")
	require.NoError(t, err)
	assert.Empty(t, f.destroyed)
}

// A VM whose run record exists but is unreadable (corrupt JSON) must be treated
// as fail-safe: gc must NOT destroy it, because it could be a live run whose
// record was merely corrupted. Destroying it would be irreversible data loss.
func TestGC_DoesNotDestroyVMBehindCorruptRecord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false

	dir, err := run.StoreDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(dir+"/run_corrupt.json", []byte("{ not valid json"), 0o600))

	f := &fakeGCAdapter{
		id:        "hetzner-vm",
		resources: []adapter.ResourceInfo{{ResourceID: "srv-live", Provider: "hetzner", RunID: "run_corrupt", Tags: map[string]string{"dispatcher": "true"}}},
	}
	withGCAdapter(t, f)

	_, _, err = executeCommand("gc", "--yes")
	require.NoError(t, err)
	assert.Empty(t, f.destroyed, "must not destroy a VM whose run record is unreadable")
}

// If gc cannot even enumerate the run records, it must abort — treating an empty
// listing as "no active runs" would misclassify every live VM as an orphan and
// destroy the whole fleet on a single transient FS error.
func TestGC_AbortsWhenRunRecordsCannotBeEnumerated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	gcFlags.dryRun = false
	gcFlags.force = false

	// Plant a regular file where the runs directory must be, so ListRecords fails.
	stateDir := filepath.Join(home, ".dispatcher")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "runs"), []byte("x"), 0o600))

	f := &fakeGCAdapter{
		id:        "hetzner-vm",
		resources: []adapter.ResourceInfo{{ResourceID: "srv-live", Provider: "hetzner", RunID: "run_live", Tags: map[string]string{"dispatcher": "true"}}},
	}
	withGCAdapter(t, f)

	_, _, err := executeCommand("gc", "--yes")
	require.Error(t, err, "gc must refuse to run when run records can't be enumerated")
	assert.Empty(t, f.destroyed, "nothing destroyed when active runs are unknowable")
}

// A dispatcher-owned resource with NO run-id is standing infra (e.g. a
// driver-baked GPU image) — it must be reported, never reaped.
func TestGC_StandingInfraNeverReaped(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false })

	f := &fakeGCAdapter{
		id: "gcp-vm",
		resources: []adapter.ResourceInfo{{
			ResourceID: "dispatcher-gpu-l4", Provider: "gcp",
			Kind: adapter.ResourceImage, // no RunID → standing infra
			Tags: map[string]string{"dispatcher": "true"},
		}},
	}
	withGCAdapter(t, f)

	_, _, err := executeCommand("gc", "--yes")
	require.NoError(t, err)
	assert.Empty(t, f.destroyed, "standing infra (no run-id) must never be reaped")
}

// If the run store is empty (0 records) but adapters report dispatcher-owned
// resources that reference run IDs, the state dir is almost certainly
// misconfigured (mispointed $DISPATCHER_HOME, wrong user, fresh checkout) — and
// reaping would destroy the entire live fleet. gc must refuse loudly.
func TestGC_RefusesReapWhenStoreEmptyButOrphansPresent(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // fresh, empty run store (0 records)
	gcFlags.dryRun = false
	gcFlags.force = false
	gcFlags.allowEmptyStore = false
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false; gcFlags.allowEmptyStore = false })

	f := orphanFixture() // dispatcher-owned resource referencing run_gone
	withGCAdapter(t, f)

	_, _, err := executeCommand("gc", "--yes")
	require.Error(t, err, "empty run store + owned orphans must refuse to reap")
	assert.Contains(t, err.Error(), "state dir")
	assert.Empty(t, f.destroyed, "nothing destroyed when the store is suspiciously empty")
}

// The --allow-empty-store override lets a user reap a genuine orphan whose run
// record was legitimately cleaned.
func TestGC_AllowEmptyStoreOverrideReaps(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	gcFlags.allowEmptyStore = false
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false; gcFlags.allowEmptyStore = false })

	f := orphanFixture()
	withGCAdapter(t, f)

	_, _, err := executeCommand("gc", "--yes", "--allow-empty-store")
	require.NoError(t, err)
	assert.Equal(t, []string{"srv-123"}, f.destroyed, "override permits reaping a genuine orphan from an empty store")
}

// A destroy that fails must be reported as an error, not silently counted as
// destroyed — the JSON report must show Found=2, Destroyed=1, and the error.
func TestGC_JSON_PartialFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false })

	owned := map[string]string{"dispatcher": "true"}
	f := &fakeGCAdapter{
		id: "gcp-vm",
		resources: []adapter.ResourceInfo{
			{ResourceID: "ok-1", Provider: "gcp", RunID: "run_a", Tags: owned},
			{ResourceID: "fail-1", Provider: "gcp", RunID: "run_b", Tags: owned},
		},
		destroyErr: map[string]error{"fail-1": assert.AnError},
	}
	withGCAdapter(t, f)

	stdout := captureStdout(t, func() {
		_, _, err := executeCommand("--output", "json", "gc", "--yes", "--allow-empty-store")
		require.NoError(t, err)
	})

	var r gcReport
	require.NoError(t, json.Unmarshal([]byte(stdout), &r))
	assert.Equal(t, 2, r.Found)
	assert.Equal(t, 1, r.Destroyed, "a failed destroy must not be counted")
	assert.Equal(t, []string{"ok-1"}, f.destroyed)
	var errored int
	for _, o := range r.Orphans {
		if o.Error != "" {
			errored++
		}
	}
	assert.Equal(t, 1, errored, "the failed orphan must carry its error")
}

// A failed destroy must NOT reclaim the run's per-run SSH key material — the VM
// may still be live.
func TestGC_FailedDestroyDoesNotReclaimKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false })

	keyDir, err := statedir.Subdir("keys")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(keyDir, 0o700))
	keyPath := keyDir + "/dispatcher-run_gone" // orphanFixture's RunID
	require.NoError(t, os.WriteFile(keyPath, []byte("k"), 0o600))

	f := orphanFixture()
	f.destroyErr = map[string]error{"srv-123": assert.AnError}
	withGCAdapter(t, f)

	_, _, err = executeCommand("gc", "--yes", "--allow-empty-store")
	require.NoError(t, err)
	assert.Empty(t, f.destroyed, "the failing destroy is not recorded")

	_, statErr := os.Stat(keyPath)
	assert.NoError(t, statErr, "SSH key must survive when the destroy failed (VM may be live)")
}

// A provider whose ListResources fails is warned about and skipped, not treated
// as zero resources and not aborting the whole GC.
func TestGC_ListResourcesFailureWarnsAndContinues(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = true
	t.Cleanup(func() { gcFlags.dryRun = false })

	f := &fakeGCAdapter{id: "gcp-vm", listErr: assert.AnError}
	withGCAdapter(t, f)

	_, _, err := executeCommand("gc", "--dry-run")
	require.NoError(t, err, "a listing failure must not abort gc")
	assert.Empty(t, f.destroyed)
}

// A resource dispatcher does not own (no dispatcher=true tag) must be listed
// for cost visibility but never counted as an orphan and never reaped — even
// though it, like standing infra, carries no run-id.
func TestGC_ExternalResourceListedNeverReaped(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	t.Cleanup(func() { gcFlags.dryRun = false; gcFlags.force = false })

	f := &fakeGCAdapter{
		id: "gcp-vm",
		resources: []adapter.ResourceInfo{{
			ResourceID: "team-nfs-snapshot", Provider: "gcp",
			Kind: adapter.ResourceSnapshot, MonthlyUSD: 4.10,
			Tags: map[string]string{"owner": "other-team"}, // NOT dispatcher-owned
		}},
	}
	withGCAdapter(t, f)

	stdout := captureStdout(t, func() {
		_, _, err := executeCommand("gc", "--json", "--dry-run")
		require.NoError(t, err)
	})

	assert.Empty(t, f.destroyed, "external resource must never be reaped")
	var report gcReport
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))
	assert.Equal(t, 0, report.Found, "external resource is not an orphan")
	assert.Empty(t, report.Standing, "external resource is not dispatcher standing infra")
	require.Len(t, report.External, 1)
	assert.Equal(t, "team-nfs-snapshot", report.External[0].ResourceID)
}

// A running instance is never free, so an unknown (uncatalogued, e.g. an exotic
// GPU size) instance cost must render as "cost unknown", not silently $0 —
// otherwise the costliest thing to leak looks free. Free-ish resources (a tiny
// disk) with no cost render nothing.
func TestResourceCostLabel(t *testing.T) {
	assert.Equal(t, " ~$24.80/mo",
		resourceCostLabel(adapter.ResourceInfo{Kind: adapter.ResourceInstance, MonthlyUSD: 24.8}))
	assert.Equal(t, " (cost unknown)",
		resourceCostLabel(adapter.ResourceInfo{Kind: adapter.ResourceInstance, MonthlyUSD: 0}))
	assert.Equal(t, " ~$0.40/mo",
		resourceCostLabel(adapter.ResourceInfo{Kind: adapter.ResourceDisk, MonthlyUSD: 0.4}))
	assert.Equal(t, "",
		resourceCostLabel(adapter.ResourceInfo{Kind: adapter.ResourceFirewall, MonthlyUSD: 0}))
}

// ---- P2: --json output ----

func TestJSONOutput_List(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rec := &run.RunRecord{ID: "run_json01", TargetID: "local-process", State: types.RunStateCompleted}
	r := run.RunFromRecord(rec)
	_, err := r.Save()
	require.NoError(t, err)

	stdout := captureStdout(t, func() {
		_, _, err := executeCommand("list", "--output", "json")
		require.NoError(t, err)
	})

	assert.NotContains(t, stdout, "\x1b[")
	var records []run.RunRecord
	require.NoError(t, json.Unmarshal([]byte(stdout), &records))
	require.Len(t, records, 1)
	assert.Equal(t, "run_json01", records[0].ID)
}

func TestJSONOutput_Status(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rec := &run.RunRecord{ID: "run_json02", TargetID: "local-process", State: types.RunStateCompleted}
	r := run.RunFromRecord(rec)
	_, err := r.Save()
	require.NoError(t, err)

	stdout := captureStdout(t, func() {
		_, _, err := executeCommand("status", "run_json02", "--json")
		require.NoError(t, err)
	})

	assert.NotContains(t, stdout, "\x1b[")
	var loaded run.RunRecord
	require.NoError(t, json.Unmarshal([]byte(stdout), &loaded))
	assert.Equal(t, "run_json02", loaded.ID)
}

func TestJSONOutput_Plan(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(dir+"/main.py", []byte(`print("hi")`), 0o644))

	stdout := captureStdout(t, func() {
		_, _, err := executeCommand("plan", dir, "--output", "json")
		require.NoError(t, err)
	})

	assert.NotContains(t, stdout, "\x1b[")
	var p types.Plan
	require.NoError(t, json.Unmarshal([]byte(stdout), &p))
	assert.NotEmpty(t, p.Metadata.ID)
}

// TestJSONUnsupportedCommandErrors covers the no-silent-failure rule: --json on
// a command that doesn't emit JSON must error rather than print prose.
func TestJSONUnsupportedCommandErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	defer func() { rootFlags.output = "text"; rootFlags.json = false }()

	// `logs` streams output and will never emit JSON — a good "unsupported" case.
	_, _, err := executeCommand("logs", "run_whatever", "--json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

// captureStdout redirects os.Stdout for the duration of fn and returns what
// was written. emitJSON writes to os.Stdout directly, so the executeCommand
// buffer doesn't see it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	prev := os.Stdout
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = pw

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(pr)
		done <- string(b)
	}()

	fn()
	pw.Close()
	os.Stdout = prev
	return <-done
}
