package run

import (
	"encoding/json"
	"testing"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSerializableState implements adapter.SerializableState for testing.
type mockSerializableState struct {
	VMID    string `json:"vmId"`
	IP      string `json:"ip"`
	KeyPath string `json:"keyPath"`
}

func (m *mockSerializableState) MarshalHandleState() (json.RawMessage, error) {
	return json.Marshal(m)
}

func TestPersistHandle_Serializable(t *testing.T) {
	r := NewRun(testPlan())
	r.Handle = &adapter.RunHandle{
		ID:       "vm-123",
		TargetID: "aws-vm",
		State: &mockSerializableState{
			VMID:    "i-abc123",
			IP:      "1.2.3.4",
			KeyPath: "/tmp/key.pem",
		},
	}

	require.NoError(t, r.PersistHandle())

	assert.Equal(t, "vm-123", r.HandleID)
	assert.NotEmpty(t, r.HandleState)

	// Verify the serialized state is valid JSON
	var deserialized mockSerializableState
	require.NoError(t, json.Unmarshal(r.HandleState, &deserialized))
	assert.Equal(t, "i-abc123", deserialized.VMID)
	assert.Equal(t, "1.2.3.4", deserialized.IP)
	assert.Equal(t, "/tmp/key.pem", deserialized.KeyPath)
}

func TestPersistHandle_NonSerializable(t *testing.T) {
	r := NewRun(testPlan())
	r.Handle = &adapter.RunHandle{
		ID:       "local-123",
		TargetID: "local-process",
		State:    "opaque-state", // plain string, not SerializableState
	}

	require.NoError(t, r.PersistHandle())

	assert.Equal(t, "local-123", r.HandleID)
	assert.Nil(t, r.HandleState) // not serialized
}

func TestPersistHandle_NilHandle(t *testing.T) {
	r := NewRun(testPlan())
	require.NoError(t, r.PersistHandle())
	assert.Empty(t, r.HandleID)
}

func TestDurableRunRecord_SaveAndLoad(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	r := NewRun(testPlan())
	r.Lifecycle = LifecycleLongRunning
	r.HandleID = "vm-456"
	r.HandleState = json.RawMessage(`{"vmId":"i-xyz789","ip":"5.6.7.8"}`)
	r.LogFile = "/home/user/.dispatcher/runs/run_1.log"

	_, err := r.Save()
	require.NoError(t, err)

	loaded, err := LoadRecord(r.ID)
	require.NoError(t, err)

	assert.Equal(t, LifecycleLongRunning, loaded.Lifecycle)
	assert.Equal(t, "vm-456", loaded.HandleID)
	assert.JSONEq(t, `{"vmId":"i-xyz789","ip":"5.6.7.8"}`, string(loaded.HandleState))
	assert.Equal(t, "/home/user/.dispatcher/runs/run_1.log", loaded.LogFile)
}

func TestDurableRunRecord_BackwardCompatible(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Save a run without durable fields (like existing runs)
	r := NewRun(testPlan())
	_, err := r.Save()
	require.NoError(t, err)

	// Load it back — new fields should be zero values
	loaded, err := LoadRecord(r.ID)
	require.NoError(t, err)

	assert.Empty(t, loaded.HandleID)
	assert.Nil(t, loaded.HandleState)
	assert.Empty(t, loaded.Lifecycle)
	assert.Zero(t, loaded.WatchdogTTL)
	assert.True(t, loaded.LastHeartbeat.IsZero())
	assert.Empty(t, loaded.LogFile)
}

func TestLifecycleForWorkload(t *testing.T) {
	assert.Equal(t, LifecycleLongRunning, LifecycleForWorkload(types.WorkloadKindService))
	assert.Equal(t, LifecycleEphemeral, LifecycleForWorkload(types.WorkloadKindScript))
	assert.Equal(t, LifecycleEphemeral, LifecycleForWorkload(types.WorkloadKindJob))
	assert.Equal(t, LifecycleEphemeral, LifecycleForWorkload(types.WorkloadKindGPUJob))
	assert.Equal(t, LifecycleEphemeral, LifecycleForWorkload(types.WorkloadKindSandbox))
	assert.Equal(t, LifecycleEphemeral, LifecycleForWorkload(types.WorkloadKindContainer))
}

func TestTransition_StoppingState(t *testing.T) {
	r := NewRun(testPlan())
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))

	// Running → Stopping
	require.NoError(t, r.Transition(types.RunStateStopping))
	assert.Equal(t, types.RunStateStopping, r.GetState())

	// Stopping → CleaningUp → Completed
	require.NoError(t, r.Transition(types.RunStateCleaningUp))
	require.NoError(t, r.Transition(types.RunStateCompleted))
}
