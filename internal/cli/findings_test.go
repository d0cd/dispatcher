package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/approval"
	"github.com/d0cd/dispatcher/internal/run"
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
	id        string
	resources []adapter.ResourceInfo
	destroyed []string
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
	return f.resources, nil
}
func (f *fakeGCAdapter) DestroyResource(_ context.Context, id string) error {
	f.destroyed = append(f.destroyed, id)
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
			{ResourceID: "srv-123", Provider: "hetzner", RunID: "run_gone"},
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

	_, _, err := executeCommand("gc")
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

	_, _, err := executeCommand("gc")
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

	_, _, err := executeCommand("gc")
	require.NoError(t, err)
	assert.Equal(t, []string{"srv-123"}, f.destroyed)
}

func TestGC_YesFlagDestroysWithoutPrompt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gcFlags.dryRun = false
	gcFlags.force = false
	f := orphanFixture()
	withGCAdapter(t, f)

	_, _, err := executeCommand("gc", "--yes")
	require.NoError(t, err)
	assert.Equal(t, []string{"srv-123"}, f.destroyed)
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
