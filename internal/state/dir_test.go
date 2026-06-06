package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDir_HomeFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DISPATCHER_HOME", "")
	chdirTo(t, home)

	d, err := Dir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".dispatcher"), d)
	assert.DirExists(t, d)
}

func TestDir_EnvOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "custom")
	t.Setenv("DISPATCHER_HOME", override)

	d, err := Dir()
	require.NoError(t, err)
	assert.Equal(t, override, d)
	assert.DirExists(t, d)
}

func TestDir_PerProjectScoped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DISPATCHER_HOME", "")

	project := resolved(t, t.TempDir())
	require.NoError(t, os.MkdirAll(filepath.Join(project, ".dispatcher"), 0o700))
	chdirTo(t, project)

	d, err := Dir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(project, ".dispatcher"), d)
}

func TestDir_WalksUpToFindProjectRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DISPATCHER_HOME", "")

	project := resolved(t, t.TempDir())
	require.NoError(t, os.MkdirAll(filepath.Join(project, ".dispatcher"), 0o700))
	sub := filepath.Join(project, "deeply", "nested", "src")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	chdirTo(t, sub)

	d, err := Dir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(project, ".dispatcher"), d)
}

func TestSubdir_CreatesAndReturnsChild(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DISPATCHER_HOME", "")
	chdirTo(t, home)

	d, err := Subdir("runs")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".dispatcher", "runs"), d)
	assert.DirExists(t, d)
}

func chdirTo(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

// resolved evaluates symlinks so test fixtures on macOS (/tmp → /private/tmp)
// match what os.Getwd reports inside the test process.
func resolved(t *testing.T, p string) string {
	t.Helper()
	out, err := filepath.EvalSymlinks(p)
	require.NoError(t, err)
	return out
}
