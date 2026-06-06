package approval

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequest_PersistsPending(t *testing.T) {
	t.Setenv("DISPATCH_HOME", t.TempDir())

	rec, path, err := RequestPending("run_abc", []types.PolicyRequirement{
		{Name: "gpu-approval", Reason: "h100:2"},
	})
	require.NoError(t, err)
	assert.Equal(t, DecisionPending, rec.Decision)
	assert.FileExists(t, path)

	loaded, err := Load("run_abc")
	require.NoError(t, err)
	assert.Equal(t, "run_abc", loaded.RunID)
	assert.Equal(t, DecisionPending, loaded.Decision)
	assert.Len(t, loaded.Requirements, 1)
}

func TestResolve_MarksApproved(t *testing.T) {
	t.Setenv("DISPATCH_HOME", t.TempDir())

	_, _, err := RequestPending("run_xyz", []types.PolicyRequirement{{Name: "budget"}})
	require.NoError(t, err)

	resolved, err := Resolve("run_xyz", DecisionApproved, "alice")
	require.NoError(t, err)
	assert.Equal(t, DecisionApproved, resolved.Decision)
	assert.Equal(t, "alice", resolved.Decider)
	assert.False(t, resolved.DecidedAt.IsZero())

	// Idempotency: resolving again must error so we never overwrite an audit decision.
	_, err = Resolve("run_xyz", DecisionDenied, "bob")
	assert.Error(t, err)
}

func TestListPending_FiltersResolved(t *testing.T) {
	t.Setenv("DISPATCH_HOME", t.TempDir())

	_, _, err := RequestPending("run_pending", []types.PolicyRequirement{{Name: "gpu"}})
	require.NoError(t, err)
	_, _, err = RequestPending("run_resolved", []types.PolicyRequirement{{Name: "budget"}})
	require.NoError(t, err)
	_, err = Resolve("run_resolved", DecisionApproved, "")
	require.NoError(t, err)

	pending, err := ListPending()
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, "run_pending", pending[0].RunID)
}
