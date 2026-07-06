package adapter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeBuildFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestBuildDigest_DeterministicAndContentSensitive(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	writeBuildFile(t, df, "FROM alpine\n")
	writeBuildFile(t, filepath.Join(dir, "app.py"), "print(1)\n")

	d1, err := buildDigest(df, dir)
	require.NoError(t, err)
	require.Len(t, d1, 12)

	d2, err := buildDigest(df, dir)
	require.NoError(t, err)
	assert.Equal(t, d1, d2, "the same tree hashes identically")

	// A source edit that keeps the file the same SIZE must still change the key
	// (proves it hashes content, not just metadata).
	writeBuildFile(t, filepath.Join(dir, "app.py"), "print(2)\n")
	d3, err := buildDigest(df, dir)
	require.NoError(t, err)
	assert.NotEqual(t, d1, d3, "a content change busts the cache key")

	writeBuildFile(t, df, "FROM alpine:3.20\n")
	d4, err := buildDigest(df, dir)
	require.NoError(t, err)
	assert.NotEqual(t, d3, d4, "a Dockerfile change busts the cache key")
}

func TestBuildDigest_IgnoresGitChurn(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	writeBuildFile(t, df, "FROM alpine\n")
	writeBuildFile(t, filepath.Join(dir, "app.py"), "x\n")

	d1, err := buildDigest(df, dir)
	require.NoError(t, err)

	writeBuildFile(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/main\n")
	d2, err := buildDigest(df, dir)
	require.NoError(t, err)
	assert.Equal(t, d1, d2, ".git churn must not bust the cache key")
}

func TestBuildDigest_MissingDockerfile(t *testing.T) {
	_, err := buildDigest(filepath.Join(t.TempDir(), "nope"), t.TempDir())
	require.Error(t, err)
}
