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
