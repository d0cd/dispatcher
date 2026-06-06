package cloudvm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimaIdentityPath_UsesLIMA_HOME(t *testing.T) {
	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "_config")
	require.NoError(t, os.MkdirAll(cfgDir, 0o755))
	keyPath := filepath.Join(cfgDir, "user")
	require.NoError(t, os.WriteFile(keyPath, []byte("fake key"), 0o600))

	t.Setenv("LIMA_HOME", tmp)

	got, err := limaIdentityPath()
	require.NoError(t, err)
	assert.Equal(t, keyPath, got)
}

func TestLimaIdentityPath_ErrorsWhenMissing(t *testing.T) {
	t.Setenv("LIMA_HOME", t.TempDir())
	_, err := limaIdentityPath()
	assert.Error(t, err, "missing identity file should surface a clear error rather than returning a phantom path")
	assert.Contains(t, err.Error(), "Lima identity")
}

func TestLimaSSHUser_NonEmpty(t *testing.T) {
	// On every reasonable environment, this should return a real username.
	// Test the fallback shape rather than pinning to a specific value.
	u := limaSSHUser()
	assert.NotEmpty(t, u, "Lima SSH user must always resolve to something")
}
