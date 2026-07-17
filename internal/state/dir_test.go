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

// ensureSecureDir must tighten a pre-existing world-accessible state dir to 0700,
// so a dir left loose by an earlier umask/version can't leak run state (SSH keys,
// approval records) to other local users.
func TestEnsureSecureDir_TightensLoosePerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.MkdirAll(dir, 0o755)) // group/world-readable
	require.NoError(t, ensureSecureDir(dir))
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "a pre-existing loose state dir is tightened to 0700")
}

func TestEnsureSecureDir_RejectsNonDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "afile")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	require.Error(t, ensureSecureDir(f), "a non-directory path must fail closed")
}

// validateHomeOverride is the DISPATCHER_HOME guard: it must reject a relative
// path and any traversal segment, so the override can't be aimed outside an
// intended tree.
func TestValidateHomeOverride(t *testing.T) {
	require.Error(t, validateHomeOverride("relative/path"), "must be absolute")
	require.Error(t, validateHomeOverride("/abs/../escape"), "must reject a .. segment")
	require.NoError(t, validateHomeOverride("/abs/clean/path"))
}
