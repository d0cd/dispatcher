package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/types"
)

func TestTrace_EmitsChromeTrace(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p := &types.Plan{
		Metadata:       types.PlanMetadata{ID: "plan_trace"},
		Recommendation: &types.Recommendation{Target: "t"},
	}
	r := run.NewRun(p)
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))
	r.MarkTerminal(types.RunStateCompleted)
	_, err := r.Save()
	require.NoError(t, err)

	var runErr error
	out := captureStdout(t, func() { runErr = runTraceByID(r.ID) })
	require.NoError(t, runErr)

	var doc run.TraceOutput
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "output must be valid Chrome trace JSON")
	assert.Equal(t, "ms", doc.DisplayTimeUnit)

	names := map[string]bool{}
	for _, e := range doc.TraceEvents {
		if e.Ph == "X" {
			names[e.Name] = true
		}
	}
	assert.True(t, names["preparing"], "the provisioning/preparing phase appears")
	assert.True(t, names["running"])
	assert.True(t, names["completed"])
}

func TestTrace_MissingRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	assert.Error(t, runTraceByID("run_nope"))
}
