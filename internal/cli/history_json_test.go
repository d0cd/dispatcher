package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/cost"
)

func TestHistory_JSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	h, err := cost.NewHistoryStore()
	require.NoError(t, err)
	require.NoError(t, h.Record(cost.RunHistory{TargetID: "local-process", Success: true, ActualCost: 0}))
	require.NoError(t, h.Record(cost.RunHistory{TargetID: "aws-vm", Success: true, ActualCost: 0.42}))

	var runErr error
	out := captureStdout(t, func() { _, _, runErr = executeCommand("--output", "json", "history") })
	require.NoError(t, runErr)

	var doc struct {
		Entries int                         `json:"entries"`
		Targets map[string]cost.TargetStats `json:"targets"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "history --json must emit valid JSON")
	assert.Equal(t, 2, doc.Entries)
	assert.Contains(t, doc.Targets, "local-process")
	assert.Contains(t, doc.Targets, "aws-vm")
	assert.Equal(t, 1, doc.Targets["aws-vm"].TotalRuns)
}

func TestHistory_JSON_Empty(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var runErr error
	out := captureStdout(t, func() { _, _, runErr = executeCommand("--output", "json", "history") })
	require.NoError(t, runErr)

	var doc struct {
		Entries int `json:"entries"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "empty history still emits valid JSON, not prose")
	assert.Equal(t, 0, doc.Entries)
}
