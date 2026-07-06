package cost

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlakiness(t *testing.T) {
	h := &HistoryStore{}
	add := func(name, target string, ok bool) {
		h.entries = append(h.entries, RunHistory{WorkloadName: name, TargetID: target, Success: ok})
	}

	// Always passes → not flaky.
	add("steady", "t1", true)
	add("steady", "t1", true)
	assert.False(t, h.Flakiness("steady", "t1").Flaky)

	// Always fails → broken, not flaky (a consistent failure is a different signal).
	add("broken", "t1", false)
	add("broken", "t1", false)
	broken := h.Flakiness("broken", "t1")
	assert.False(t, broken.Flaky)
	assert.Equal(t, 2, broken.Failures)

	// Mixed pass/fail → flaky.
	add("wobbly", "t1", true)
	add("wobbly", "t1", false)
	add("wobbly", "t1", true)
	wobbly := h.Flakiness("wobbly", "t1")
	assert.True(t, wobbly.Flaky)
	assert.Equal(t, 3, wobbly.Runs)
	assert.Equal(t, 1, wobbly.Failures)

	// Single run is never flaky (no basis to compare).
	add("once", "t1", false)
	assert.False(t, h.Flakiness("once", "t1").Flaky)
}

func TestFlakiness_ScopedToWorkloadAndTarget(t *testing.T) {
	h := &HistoryStore{}
	h.entries = []RunHistory{
		{WorkloadName: "app", TargetID: "t1", Success: true},
		{WorkloadName: "app", TargetID: "t1", Success: false},
		{WorkloadName: "app", TargetID: "t2", Success: true}, // other target
		{WorkloadName: "other", TargetID: "t1", Success: false},
	}
	rep := h.Flakiness("app", "t1")
	assert.Equal(t, 2, rep.Runs, "only this workload+target counts")
	assert.True(t, rep.Flaky)
}
