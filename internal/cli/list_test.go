package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/run"
)

func writeCorruptRecord(t *testing.T) {
	t.Helper()
	dir, err := run.StoreDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "run_corrupt.json"), []byte("{ not json"), 0o600))
}

// A corrupt run record must still appear in `list` (flagged UNREADABLE) — it may
// be a still-billing run, and gc now refuses to reap it, so it must be visible.
func TestList_SurfacesUnreadableRecord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeCorruptRecord(t)

	out := captureStdout(t, func() { _, _, _ = executeCommand("list") })

	assert.Contains(t, out, "run_corrupt", "an unreadable record must still be listed")
	assert.Contains(t, out, "UNREADABLE")
}

func TestList_JSONIncludesUnreadableRecord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeCorruptRecord(t)

	out := captureStdout(t, func() { _, _, _ = executeCommand("list", "--json") })

	assert.Contains(t, out, "run_corrupt")
	assert.Contains(t, out, "unreadable")
}
