package run

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDurableAdapter implements adapter.DurableAdapter for testing.
type mockDurableAdapter struct {
	id      string
	lastTTL time.Duration // records the ttl passed to the most recent ExtendWatchdog
}

func (m *mockDurableAdapter) ID() string { return m.id }
func (m *mockDurableAdapter) Validate(_ context.Context, _ types.WorkloadSpec) (types.ValidationResult, error) {
	return types.ValidationResult{Schema: types.ValidationPass}, nil
}
func (m *mockDurableAdapter) EstimateCost(_ context.Context, _ types.WorkloadSpec) (types.CostEstimate, error) {
	return types.CostEstimate{}, nil
}
func (m *mockDurableAdapter) Prepare(_ context.Context, _ *types.Plan) error { return nil }
func (m *mockDurableAdapter) Execute(_ context.Context, _ *types.Plan) (*adapter.RunHandle, error) {
	return nil, nil
}
func (m *mockDurableAdapter) Status(_ context.Context, _ *adapter.RunHandle) (types.RunState, error) {
	return types.RunStateRunning, nil
}
func (m *mockDurableAdapter) Logs(_ context.Context, _ *adapter.RunHandle, _ io.Writer) error {
	return nil
}
func (m *mockDurableAdapter) Artifacts(_ context.Context, _ *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
	return nil, nil
}
func (m *mockDurableAdapter) Terminate(_ context.Context, _ *adapter.RunHandle) error { return nil }
func (m *mockDurableAdapter) Cleanup(_ context.Context, _ *adapter.RunHandle) (*adapter.CleanupResult, error) {
	return &adapter.CleanupResult{Success: true}, nil
}

// DurableAdapter methods
func (m *mockDurableAdapter) Reconnect(_ context.Context, handleID string, state json.RawMessage) (*adapter.RunHandle, error) {
	return &adapter.RunHandle{
		ID:       handleID,
		TargetID: m.id,
		State:    &mockSerializableState{},
	}, nil
}
func (m *mockDurableAdapter) ExtendWatchdog(_ context.Context, _ *adapter.RunHandle, ttl time.Duration) (time.Time, error) {
	m.lastTTL = ttl
	return time.Now().Add(ttl), nil
}
func (m *mockDurableAdapter) ListResources(_ context.Context) ([]adapter.ResourceInfo, error) {
	return nil, nil
}
func (m *mockDurableAdapter) DestroyResource(_ context.Context, _ adapter.ResourceInfo) error {
	return nil
}

func TestReconnectToRun_TerminalState(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Save a completed run
	r := NewRun(testPlan())
	r.mu.Lock()
	r.State = types.RunStateCompleted
	r.FinishedAt = time.Now().UTC()
	r.mu.Unlock()
	_, err := r.Save()
	require.NoError(t, err)

	// Reconnect should return the run without an adapter
	ctx := context.Background()
	loaded, a, err := ReconnectToRun(ctx, r.ID, func(targetID string) (adapter.TargetAdapter, error) {
		return &mockDurableAdapter{id: targetID}, nil
	})
	require.NoError(t, err)
	assert.Nil(t, a)
	assert.Equal(t, types.RunStateCompleted, loaded.GetState())
}

func TestReconnectToRun_DurableAdapter(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Save a running run with handle state
	r := NewRun(testPlan())
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))
	r.HandleID = "vm-reconnect-test"
	r.HandleState = json.RawMessage(`{"vmId":"i-test","ip":"1.2.3.4"}`)
	_, err := r.Save()
	require.NoError(t, err)

	// Reconnect with a durable adapter
	ctx := context.Background()
	loaded, a, err := ReconnectToRun(ctx, r.ID, func(targetID string) (adapter.TargetAdapter, error) {
		return &mockDurableAdapter{id: targetID}, nil
	})
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.NotNil(t, loaded.Handle)
	assert.Equal(t, "vm-reconnect-test", loaded.Handle.ID)
}

func TestReconnectToRun_NotFound(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	ctx := context.Background()
	_, _, err := ReconnectToRun(ctx, "nonexistent", func(targetID string) (adapter.TargetAdapter, error) {
		return nil, nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRunFromRecord(t *testing.T) {
	rec := &RunRecord{
		ID:          "run_42",
		PlanID:      "plan_42",
		TargetID:    "aws-vm",
		Owner:       "test-user",
		State:       types.RunStateRunning,
		Lifecycle:   LifecycleLongRunning,
		HandleID:    "vm-abc",
		HandleState: json.RawMessage(`{"vmId":"i-abc"}`),
	}

	r := RunFromRecord(rec)
	assert.Equal(t, "run_42", r.ID)
	assert.Equal(t, "plan_42", r.PlanID)
	assert.Equal(t, "aws-vm", r.TargetID)
	assert.Equal(t, LifecycleLongRunning, r.Lifecycle)
	assert.Equal(t, "vm-abc", r.HandleID)
	assert.JSONEq(t, `{"vmId":"i-abc"}`, string(r.HandleState))
}
