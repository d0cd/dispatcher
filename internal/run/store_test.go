package run

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/approval"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunSaveAndLoad(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	r := NewRun(testPlan())
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))

	path, err := r.Save()
	require.NoError(t, err)
	assert.FileExists(t, path)

	loaded, err := LoadRecord(r.ID)
	require.NoError(t, err)
	assert.Equal(t, r.ID, loaded.ID)
	assert.Equal(t, r.PlanID, loaded.PlanID)
	assert.Equal(t, r.TargetID, loaded.TargetID)
	assert.Equal(t, types.RunStateValidated, loaded.State)
}

func TestLoadRecordNotFound(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	_, err := LoadRecord("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	// The not-found message must not leak the internal state-dir path and
	// should point the user at `dispatcher list`.
	assert.NotContains(t, err.Error(), tmpHome)
	assert.NotContains(t, err.Error(), ".json")
	assert.Contains(t, err.Error(), "dispatcher list")
}

// TestSaveLoadPreservesApproval guards against the reconnect/resave path
// silently dropping the persisted approval audit record: a run is saved with
// an Approval, reconstructed via RunFromRecord (as status/stop/list do), then
// re-saved — the record must survive both round-trips.
func TestSaveLoadPreservesApproval(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	r := NewRun(testPlan())
	r.Approval = &approval.Record{
		RunID:    r.ID,
		Decision: approval.DecisionApproved,
		Decider:  "interactive:alice",
	}
	_, err := r.Save()
	require.NoError(t, err)

	rec, err := LoadRecord(r.ID)
	require.NoError(t, err)
	require.NotNil(t, rec.Approval)

	// Simulate status/stop/list refreshing a reconnected run and re-saving.
	reconstructed := RunFromRecord(rec)
	_, err = reconstructed.Save()
	require.NoError(t, err)

	rec2, err := LoadRecord(r.ID)
	require.NoError(t, err)
	require.NotNil(t, rec2.Approval, "approval record erased on reconnect+resave")
	assert.Equal(t, "interactive:alice", rec2.Approval.Decider)
}

func TestListRecords(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	r1 := NewRun(testPlan())
	r2 := NewRun(testPlan())

	_, err := r1.Save()
	require.NoError(t, err)
	_, err = r2.Save()
	require.NoError(t, err)

	ids, err := ListRecords()
	require.NoError(t, err)
	assert.Len(t, ids, 2)
}

func TestRunSaveWithError(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	r := NewRun(testPlan())
	r.SetError(types.RunStateExecutionFailed, assert.AnError)

	_, err := r.Save()
	require.NoError(t, err)

	loaded, err := LoadRecord(r.ID)
	require.NoError(t, err)
	assert.Equal(t, types.RunStateExecutionFailed, loaded.State)
	assert.NotEmpty(t, loaded.Error)
}
