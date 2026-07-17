package run

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

func tracePlan() *types.Plan {
	return &types.Plan{
		Metadata:       types.PlanMetadata{ID: "plan_trace"},
		Recommendation: &types.Recommendation{Target: "t"},
	}
}

func TestRun_TimelineRecordsPhases(t *testing.T) {
	r := NewRun(tracePlan())
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))

	rec := r.ToRecord()
	var states []types.RunState
	for _, m := range rec.Timeline {
		states = append(states, m.State)
	}
	assert.Equal(t, []types.RunState{
		types.RunStateCreated,
		types.RunStatePlanning,
		types.RunStateValidated,
		types.RunStatePreparing,
		types.RunStateRunning,
	}, states, "the timeline records entry into every phase, seeded with Created")

	for i := 1; i < len(rec.Timeline); i++ {
		assert.False(t, rec.Timeline[i].EnteredAt.Before(rec.Timeline[i-1].EnteredAt),
			"phase entry times must be monotonic")
	}
}

func TestRun_TimelineRecordsFailure(t *testing.T) {
	r := NewRun(tracePlan())
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))
	r.SetError(types.RunStateExecutionFailed, assert.AnError)

	rec := r.ToRecord()
	last := rec.Timeline[len(rec.Timeline)-1]
	assert.Equal(t, types.RunStateExecutionFailed, last.State,
		"a failure set outside Transition must still land on the timeline")
}

func phaseEvents(tr TraceOutput) []TraceEvent {
	var out []TraceEvent
	for _, e := range tr.TraceEvents {
		if e.Ph == "X" {
			out = append(out, e)
		}
	}
	return out
}

func TestBuildTrace(t *testing.T) {
	base := time.Unix(1_000_000, 0).UTC()
	rec := &RunRecord{
		ID:         "run_x",
		FinishedAt: base.Add(10 * time.Second),
		Timeline: []PhaseMark{
			{State: types.RunStatePreparing, EnteredAt: base},
			{State: types.RunStateRunning, EnteredAt: base.Add(3 * time.Second)},
			{State: types.RunStateCompleted, EnteredAt: base.Add(10 * time.Second)},
		},
	}

	tr := BuildTrace(rec)
	assert.Equal(t, "ms", tr.DisplayTimeUnit)

	events := phaseEvents(tr)
	require.Len(t, events, 3)

	assert.Equal(t, "preparing", events[0].Name)
	assert.Equal(t, base.UnixMicro(), events[0].Ts)
	assert.Equal(t, int64(3_000_000), events[0].Dur, "preparing spans until running begins")

	assert.Equal(t, "running", events[1].Name)
	assert.Equal(t, int64(7_000_000), events[1].Dur, "running spans until the terminal phase")

	assert.Equal(t, "completed", events[2].Name)
	assert.Equal(t, int64(0), events[2].Dur, "the terminal phase closes at FinishedAt")
}

func TestBuildTrace_OpenRunHasNoNegativeDuration(t *testing.T) {
	base := time.Unix(1_000_000, 0).UTC()
	rec := &RunRecord{
		ID: "run_open",
		// No FinishedAt: run still in progress.
		Timeline: []PhaseMark{
			{State: types.RunStatePreparing, EnteredAt: base},
			{State: types.RunStateRunning, EnteredAt: base.Add(2 * time.Second)},
		},
	}
	events := phaseEvents(BuildTrace(rec))
	require.Len(t, events, 2)
	assert.Equal(t, int64(2_000_000), events[0].Dur)
	assert.Equal(t, int64(0), events[1].Dur, "the open final phase has zero, never negative, duration")
}
