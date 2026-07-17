package adapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The extra-env parameter injects runtime env (e.g. a shard's SHARD_INDEX)
// alongside the workload's .env, winning on conflict. Every adapter's env
// assembler must honor it consistently.

func TestInjectDotEnv_ExtraWinsOverDotEnvAndBase(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("SHARD_INDEX=fromdotenv\nKEEP=1\n"), 0o644))

	env, err := injectDotEnv([]string{"SHARD_INDEX=frombase", "PATH=/bin"}, dir,
		map[string]string{"SHARD_INDEX": "3", "SHARD_COUNT": "8"})
	require.NoError(t, err)

	joined := strings.Join(env, "\n")
	assert.Contains(t, joined, "SHARD_INDEX=3", "extra wins over both base and .env")
	assert.NotContains(t, joined, "SHARD_INDEX=frombase")
	assert.NotContains(t, joined, "SHARD_INDEX=fromdotenv")
	assert.Contains(t, joined, "SHARD_COUNT=8")
	assert.Contains(t, joined, "KEEP=1")
	assert.Contains(t, joined, "PATH=/bin")
}

func TestInjectDotEnv_ExtraWithNoDotEnv(t *testing.T) {
	env, err := injectDotEnv([]string{"PATH=/bin"}, t.TempDir(),
		map[string]string{"SHARD_INDEX": "0"})
	require.NoError(t, err)
	assert.Contains(t, strings.Join(env, "\n"), "SHARD_INDEX=0", "extra applies even when there's no .env")
}

func TestWriteDotEnvFile_IncludesExtra(t *testing.T) {
	path, cleanup, err := WriteDotEnvFile(t.TempDir(), map[string]string{"SHARD_INDEX": "2"})
	require.NoError(t, err)
	require.NotEmpty(t, path, "extra env alone should produce a file even with no .env")
	defer cleanup()
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(body), "SHARD_INDEX=2\n")
}

func TestDotEnvExportScript_IncludesExtra(t *testing.T) {
	script, err := DotEnvExportScript(t.TempDir(), map[string]string{"SHARD_COUNT": "5"})
	require.NoError(t, err)
	assert.Contains(t, script, "SHARD_COUNT", "shard identity is exported for the runner")
	assert.Contains(t, script, "5")
}

func TestDotEnvFileLines_IncludesExtra(t *testing.T) {
	lines, err := DotEnvFileLines(t.TempDir(), map[string]string{"SHARD_INDEX": "7"})
	require.NoError(t, err)
	assert.Contains(t, lines, "SHARD_INDEX=7")
}
