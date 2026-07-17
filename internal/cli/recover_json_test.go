package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
)

func TestRecover_JSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	withGCAdapter(t, &fakeGCAdapter{
		id: "hetzner-vm",
		resources: []adapter.ResourceInfo{
			{ResourceID: "srv-1", Provider: "hetzner", RunID: "run_a"}, // no local record → missing
			{ResourceID: "srv-2", Provider: "hetzner"},                 // untagged
		},
	})

	var runErr error
	out := captureStdout(t, func() { _, _, runErr = executeCommand("--output", "json", "recover") })
	require.NoError(t, runErr)

	var doc struct {
		Total      int      `json:"total"`
		Attachable []string `json:"attachable"`
		VMs        []struct {
			ResourceID  string `json:"resourceId"`
			Provider    string `json:"provider"`
			RunID       string `json:"runId"`
			LocalRecord string `json:"localRecord"`
			Attachable  bool   `json:"attachable"`
		} `json:"vms"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "recover --json must emit valid JSON")
	assert.Equal(t, 2, doc.Total)
	assert.Empty(t, doc.Attachable, "no local records exist, so nothing is attachable")

	byID := map[string]string{}
	for _, v := range doc.VMs {
		byID[v.ResourceID] = v.LocalRecord
		assert.Equal(t, "hetzner", v.Provider)
	}
	assert.Equal(t, "missing", byID["srv-1"], "tagged VM with no local record is 'missing'")
	assert.Equal(t, "", byID["srv-2"], "untagged VM has no local-record status")
}

func TestRecover_JSON_NoAdapters(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prev := durableAdaptersFn
	durableAdaptersFn = func() []adapter.DurableAdapter { return nil }
	t.Cleanup(func() { durableAdaptersFn = prev })

	var runErr error
	out := captureStdout(t, func() { _, _, runErr = executeCommand("--output", "json", "recover") })
	require.NoError(t, runErr)

	var doc struct {
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "no adapters still emits valid JSON, not prose")
	assert.Equal(t, 0, doc.Total)
}
