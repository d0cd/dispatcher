package adapter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyPath_FileAndDir(t *testing.T) {
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "a.txt"), []byte("hi"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(src, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("yo"), 0o644))

	dst := filepath.Join(t.TempDir(), "out")
	require.NoError(t, copyPath(src, dst))

	a, err := os.ReadFile(filepath.Join(dst, "a.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hi", string(a))
	b, err := os.ReadFile(filepath.Join(dst, "sub", "b.txt"))
	require.NoError(t, err)
	assert.Equal(t, "yo", string(b), "directory trees are copied recursively")
}

func TestLocalAdapter_ArtifactsCollectsOutputs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	src := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(src, "results"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(src, "results", "out.txt"), []byte("data"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(src, "model.bin"), []byte("m"), 0o644))

	h := &RunHandle{RunID: "run_local1", State: &localState{
		sourcePath: src,
		outputs:    []string{"results", "model.bin", "missing"},
	}}
	refs, err := (&LocalAdapter{}).Artifacts(context.Background(), h)
	require.NoError(t, err)
	require.Len(t, refs, 2, "results/ and model.bin collected; a never-produced output is skipped")

	// results/ (dir) is refs[0], model.bin (file) is refs[1] — order preserved.
	body, err := os.ReadFile(filepath.Join(refs[0].Path, "out.txt"))
	require.NoError(t, err)
	assert.Equal(t, "data", string(body))
	mb, err := os.ReadFile(refs[1].Path)
	require.NoError(t, err)
	assert.Equal(t, "m", string(mb))
}

func TestLocalAdapter_ArtifactsRejectsEscape(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	h := &RunHandle{RunID: "run_x", State: &localState{
		sourcePath: t.TempDir(),
		outputs:    []string{"../etc/passwd", "/abs/path"},
	}}
	refs, err := (&LocalAdapter{}).Artifacts(context.Background(), h)
	require.NoError(t, err)
	assert.Empty(t, refs, "absolute and traversal output paths are rejected")
}

// A workload runs arbitrary code and produces its own outputs; it must not be
// able to plant a symlink that makes dispatcher snapshot a file outside the
// source tree (e.g. ~/.aws/credentials) into the artifacts directory.
func TestLocalAdapter_ArtifactsDoesNotFollowSymlinkInOutputDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	secret := filepath.Join(t.TempDir(), "credentials")
	require.NoError(t, os.WriteFile(secret, []byte("SECRET"), 0o600))

	src := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(src, "results"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(src, "results", "ok.txt"), []byte("data"), 0o644))
	require.NoError(t, os.Symlink(secret, filepath.Join(src, "results", "leak")))

	h := &RunHandle{RunID: "run_symdir", State: &localState{
		sourcePath: src,
		outputs:    []string{"results"},
	}}
	refs, err := (&LocalAdapter{}).Artifacts(context.Background(), h)
	require.NoError(t, err)
	require.Len(t, refs, 1)

	// The regular file is copied; the symlinked entry is not followed.
	_, err = os.Stat(filepath.Join(refs[0].Path, "ok.txt"))
	require.NoError(t, err)
	leaked, err := os.ReadFile(filepath.Join(refs[0].Path, "leak"))
	if err == nil {
		assert.NotEqual(t, "SECRET", string(leaked), "a symlink inside an output dir must not leak its target")
	}
}

func TestLocalAdapter_ArtifactsDoesNotFollowSymlinkedOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	secret := filepath.Join(t.TempDir(), "passwd")
	require.NoError(t, os.WriteFile(secret, []byte("SECRET"), 0o600))

	src := t.TempDir()
	require.NoError(t, os.Symlink(secret, filepath.Join(src, "out")))

	h := &RunHandle{RunID: "run_symout", State: &localState{
		sourcePath: src,
		outputs:    []string{"out"},
	}}
	refs, err := (&LocalAdapter{}).Artifacts(context.Background(), h)
	require.NoError(t, err)
	assert.Empty(t, refs, "a declared output that is a symlink to an outside file must be skipped")
}

func TestLocalAdapter_ArtifactsNoOutputs(t *testing.T) {
	refs, err := (&LocalAdapter{}).Artifacts(context.Background(),
		&RunHandle{RunID: "r", State: &localState{sourcePath: t.TempDir()}})
	require.NoError(t, err)
	assert.Nil(t, refs)
}
