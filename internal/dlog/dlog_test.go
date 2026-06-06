package dlog

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogger_EmitsStructuredJSON(t *testing.T) {
	var buf bytes.Buffer
	test := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Force L() into a known state, then override.
	_ = L()
	old := logger
	defer func() { logger = old }()
	logger = test

	L().Info("run.transition", "run", "run_abc", "from", "preparing", "to", "running")

	out := strings.TrimSpace(buf.String())
	var event map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &event))
	assert.Equal(t, "run.transition", event["msg"])
	assert.Equal(t, "run_abc", event["run"])
	assert.Equal(t, "preparing", event["from"])
	assert.Equal(t, "running", event["to"])
	assert.Equal(t, "INFO", event["level"])
}
