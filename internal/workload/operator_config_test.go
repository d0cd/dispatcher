package workload

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadOperatorConfig_MissingIsEmpty(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no config file present
	c, err := LoadOperatorConfig()
	require.NoError(t, err, "a missing global config is not an error")
	assert.Empty(t, c.Secrets)
}

func TestLoadOperatorConfig_ParsesSecrets(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "dispatcher"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dispatcher", "config.yaml"),
		[]byte("secrets:\n  DISPATCHER_LAMBDA_API_KEY: [\"printf\", \"k\"]\n"), 0o600))

	c, err := LoadOperatorConfig()
	require.NoError(t, err)
	assert.Equal(t, []string{"printf", "k"}, c.Secrets["DISPATCHER_LAMBDA_API_KEY"])
}

func TestLoadOperatorConfig_MalformedFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "dispatcher"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dispatcher", "config.yaml"),
		[]byte("secrets: [not-a-map\n"), 0o600))

	_, err := LoadOperatorConfig()
	require.Error(t, err, "a malformed global config must fail closed, not silently drop secrets")
}
