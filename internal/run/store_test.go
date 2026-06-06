package run

import (
	"testing"

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
