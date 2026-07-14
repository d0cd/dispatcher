package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/plan"
	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/types"
)

// persistTerminalRunWithState writes a completed run carrying the given adapter
// HandleState, so status renders without attempting a live reconnect.
func persistTerminalRunWithState(t *testing.T, handleState string) string {
	t.Helper()
	p := &types.Plan{
		Metadata:       types.PlanMetadata{ID: "plan_status"},
		Recommendation: &types.Recommendation{Target: "test-target"},
	}
	r := run.NewRun(p)
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))
	r.HandleID = "h1"
	r.HandleState = json.RawMessage(handleState)
	r.MarkTerminal(types.RunStateCompleted)
	_, err := r.Save()
	require.NoError(t, err)
	return r.ID
}

func TestStatus_RendersAttestation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	id := persistTerminalRunWithState(t,
		`{"attestation":{"verified":true,"type":"sev-snp","measurement":"deadbeef","tcb":7,"verdict":"verified"}}`)
	var err error
	out := captureStdout(t, func() { err = runStatusByID(id) })
	require.NoError(t, err)
	assert.Contains(t, out, "Attestation:")
	assert.Contains(t, out, "sev-snp")
	assert.Contains(t, out, "deadbeef")
}

func TestStatus_RendersUnverifiedAttestation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	id := persistTerminalRunWithState(t,
		`{"attestation":{"verified":false,"verdict":"attestation off — provisioned TEE without verification"}}`)
	var err error
	out := captureStdout(t, func() { err = runStatusByID(id) })
	require.NoError(t, err)
	assert.Contains(t, out, "Attestation:")
	assert.Contains(t, out, "UNVERIFIED")
	assert.Contains(t, out, "attestation off")
}

func TestStatus_NoAttestationLineForPlainRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	id := persistTerminalRunWithState(t, `{}`)
	var err error
	out := captureStdout(t, func() { err = runStatusByID(id) })
	require.NoError(t, err)
	assert.NotContains(t, out, "Attestation:")
}

// fakeStatusAdapter is a durable adapter whose Status() and ExtendWatchdog()
// behavior is controllable, for testing the status auto-renew path.
type fakeStatusAdapter struct {
	*fakeGCAdapter
	statusErr   error
	statusState types.RunState // reported state; defaults to Running when empty
	extended    bool
}

func (f *fakeStatusAdapter) Status(context.Context, *adapter.RunHandle) (types.RunState, error) {
	if f.statusErr != nil {
		return "", f.statusErr
	}
	if f.statusState != "" {
		return f.statusState, nil
	}
	return types.RunStateRunning, nil
}

func (f *fakeStatusAdapter) Reconnect(_ context.Context, id string, _ json.RawMessage) (*adapter.RunHandle, error) {
	return &adapter.RunHandle{ID: id, TargetID: f.fakeGCAdapter.id}, nil
}

func (f *fakeStatusAdapter) ExtendWatchdog(context.Context, *adapter.RunHandle, time.Duration) (time.Time, error) {
	f.extended = true
	return time.Now().Add(time.Hour), nil
}

func persistRunningRun(t *testing.T) string {
	t.Helper()
	p := &types.Plan{
		Metadata:       types.PlanMetadata{ID: "plan_status"},
		Recommendation: &types.Recommendation{Target: "test-target"},
	}
	r := run.NewRun(p)
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))
	r.HandleID = "h1"
	r.HandleState = json.RawMessage(`{}`)
	_, err := r.Save()
	require.NoError(t, err)
	return r.ID
}

func withAdapterForTarget(t *testing.T, a adapter.TargetAdapter) {
	t.Helper()
	prev := adapterForTargetFn
	adapterForTargetFn = func(string) (adapter.TargetAdapter, error) { return a, nil }
	t.Cleanup(func() { adapterForTargetFn = prev })
}

// quietStdout redirects os.Stdout to /dev/null for the duration of the test so
// status's human output doesn't pollute the test log.
func quietStdout(t *testing.T) {
	t.Helper()
	prev := os.Stdout
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	os.Stdout = devnull
	t.Cleanup(func() { os.Stdout = prev; devnull.Close() })
}

func TestStatus_DoesNotRenewWatchdogWhenStatusFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	quietStdout(t)
	id := persistRunningRun(t)
	f := &fakeStatusAdapter{fakeGCAdapter: &fakeGCAdapter{id: "test-target"}, statusErr: errors.New("provider unreachable")}
	withAdapterForTarget(t, f)

	require.NoError(t, runStatusByID(id))
	assert.False(t, f.extended, "must not renew the watchdog when the live status could not be confirmed")
}

// When status discovers a self-terminated durable run, the runtime-scaled
// final cost must be persisted — not left at its stale pre-run value, which
// would make list/cost/bill permanently undercount the run's spend.
func TestStatus_PersistsFinalCostOnTerminalDiscovery(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	quietStdout(t)

	p := &types.Plan{
		Metadata: types.PlanMetadata{ID: "plan_finalcost"},
		Recommendation: &types.Recommendation{
			Target:        "test-target",
			EstimatedCost: types.CostEstimate{Value: 24, Currency: "USD", Confidence: types.ConfidenceHigh},
		},
		Workload: types.WorkloadSpec{DetectedKind: types.WorkloadKindService},
	}
	_, err := plan.Save(p)
	require.NoError(t, err)

	r := run.NewRun(p)
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))
	r.StartedAt = time.Now().Add(-time.Hour) // ~1h of runtime to scale from
	r.HandleID = "h1"
	r.HandleState = json.RawMessage(`{}`)
	_, err = r.Save()
	require.NoError(t, err)

	f := &fakeStatusAdapter{fakeGCAdapter: &fakeGCAdapter{id: "test-target"}, statusState: types.RunStateCompleted}
	withAdapterForTarget(t, f)

	require.NoError(t, runStatusByID(r.ID))

	rec, err := run.LoadRecord(r.ID)
	require.NoError(t, err)
	assert.Equal(t, types.RunStateCompleted, rec.State)
	assert.Greater(t, rec.Cost.Value, 0.0, "final cost must be persisted on terminal discovery")
}

func TestStatus_RenewsWatchdogWhenRunning(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	quietStdout(t)
	id := persistRunningRun(t)
	f := &fakeStatusAdapter{fakeGCAdapter: &fakeGCAdapter{id: "test-target"}}
	withAdapterForTarget(t, f)

	require.NoError(t, runStatusByID(id))
	assert.True(t, f.extended, "should renew the watchdog after confirming the run is still running")
}
