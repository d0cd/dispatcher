package workload

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDotEnv_ReadsKVPairs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte(`
# comment
API_KEY=sk-test
DATABASE_URL="postgres://localhost/db"
EMPTY=

QUOTED='single-quoted'
`), 0o644))

	got, err := LoadDotEnv(dir)
	require.NoError(t, err)
	assert.Equal(t, "sk-test", got["API_KEY"])
	assert.Equal(t, "postgres://localhost/db", got["DATABASE_URL"])
	assert.Equal(t, "single-quoted", got["QUOTED"])
	_, hasEmpty := got["EMPTY"]
	assert.True(t, hasEmpty)
}

func TestLoadDotEnv_RejectsInjectionKey(t *testing.T) {
	dir := t.TempDir()
	// A key carrying shell metacharacters would become command injection once
	// rendered into `export <key>=...` and piped to a remote shell.
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("FOO; touch /tmp/pwned =bar\n"), 0o644))

	_, err := LoadDotEnv(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key")
}

func TestLoadDotEnv_RejectsSymlink(t *testing.T) {
	// A .env symlinked at a host file would export that file's contents into the
	// remote env; refuse to follow it.
	dir := t.TempDir()
	secret := filepath.Join(dir, "host-secret")
	require.NoError(t, os.WriteFile(secret, []byte("API_KEY=leaked\n"), 0o600))
	require.NoError(t, os.Symlink(secret, filepath.Join(dir, ".env")))

	_, err := LoadDotEnv(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")
}

func TestIsValidEnvKey(t *testing.T) {
	for _, ok := range []string{"FOO", "_X", "A1_B2", "lower_case"} {
		assert.Truef(t, isValidEnvKey(ok), "%q should be valid", ok)
	}
	for _, bad := range []string{"", "1FOO", "FOO BAR", "FOO;BAR", "FOO-BAR", "FOO.BAR"} {
		assert.Falsef(t, isValidEnvKey(bad), "%q should be rejected", bad)
	}
}

func TestLoadDotEnv_MissingFileReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadDotEnv(dir)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestLoadDotEnv_LocalOverridesBase(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY=base\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env.local"), []byte("KEY=override\n"), 0o644))

	got, err := LoadDotEnv(dir)
	require.NoError(t, err)
	assert.Equal(t, "override", got["KEY"])
}
