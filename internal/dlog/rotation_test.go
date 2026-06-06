package dlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenLogFile_RotatesWhenOversized(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("DISPATCHER_HOME", tmp)

	path := filepath.Join(tmp, "dispatcher.log")
	oversized := strings.Repeat("x", maxLogBytes+1024)
	require.NoError(t, os.WriteFile(path, []byte(oversized), 0o600))

	// First openLogFile call after the oversized file exists should rotate.
	w := openLogFile()
	defer func() {
		if c, ok := w.(*os.File); ok {
			_ = c.Close()
		}
	}()

	// Rotated file should now exist; live file should be empty (we just
	// opened it for append from scratch).
	_, err := os.Stat(path + ".1")
	require.NoError(t, err, "rotated dispatcher.log.1 should exist")

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Zero(t, info.Size(), "live log should start empty after rotation")
}

func TestOpenLogFile_NoRotationUnderThreshold(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("DISPATCHER_HOME", tmp)

	path := filepath.Join(tmp, "dispatcher.log")
	small := strings.Repeat("y", 1024)
	require.NoError(t, os.WriteFile(path, []byte(small), 0o600))

	w := openLogFile()
	defer func() {
		if c, ok := w.(*os.File); ok {
			_ = c.Close()
		}
	}()

	// No rotation should have occurred.
	_, err := os.Stat(path + ".1")
	assert.True(t, os.IsNotExist(err), "no rotation expected for sub-threshold logs")

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(1024), info.Size(), "live log should be preserved as-is")
}
