package workload

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanSourceFiles_Recursive(t *testing.T) {
	dir := t.TempDir()
	// Create nested structure
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src", "api"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src", "models"), 0o755))

	writeFile(t, dir, "main.py", "print('root')")
	writeFile(t, filepath.Join(dir, "src"), "app.py", "print('src')")
	writeFile(t, filepath.Join(dir, "src", "api"), "routes.py", "print('api')")
	writeFile(t, filepath.Join(dir, "src", "models"), "user.py", "print('model')")

	files := scanSourceFiles(dir, []string{".py"})
	assert.GreaterOrEqual(t, len(files), 4)
}

func TestScanSourceFiles_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "node_modules", "foo"), 0o755))

	writeFile(t, dir, "index.js", "console.log('root')")
	writeFile(t, filepath.Join(dir, "node_modules", "foo"), "index.js", "// should be skipped")

	files := scanSourceFiles(dir, []string{".js"})
	assert.Len(t, files, 1) // only root index.js
}

func TestScanSourceFiles_SkipsVenv(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".venv", "lib"), 0o755))

	writeFile(t, dir, "main.py", "print('root')")
	writeFile(t, filepath.Join(dir, ".venv", "lib"), "site.py", "# should be skipped")

	files := scanSourceFiles(dir, []string{".py"})
	assert.Len(t, files, 1)
}

func TestScanSourceFiles_DepthLimit(t *testing.T) {
	dir := t.TempDir()
	// Create deeply nested structure
	deep := filepath.Join(dir, "a", "b", "c", "d", "e")
	require.NoError(t, os.MkdirAll(deep, 0o755))

	writeFile(t, dir, "root.py", "")
	writeFile(t, filepath.Join(dir, "a"), "a.py", "")
	writeFile(t, filepath.Join(dir, "a", "b"), "b.py", "")
	writeFile(t, filepath.Join(dir, "a", "b", "c"), "c.py", "")
	writeFile(t, deep, "deep.py", "") // beyond depth limit

	files := scanSourceFiles(dir, []string{".py"})
	// Should find root, a, b, c (depth limit is 5, so all are within range)
	assert.GreaterOrEqual(t, len(files), 4)
}

func TestScanSourceFiles_SkipsSymlinkedFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "real.py", "print('real')")
	// A symlink with a source extension pointing at a host file must not be
	// collected for inspection.
	host := filepath.Join(t.TempDir(), "secret.py")
	require.NoError(t, os.WriteFile(host, []byte("SECRET=1"), 0o600))
	require.NoError(t, os.Symlink(host, filepath.Join(dir, "link.py")))

	files := scanSourceFiles(dir, []string{".py"})
	assert.Len(t, files, 1)
	assert.Contains(t, files[0], "real.py")
}

func TestScanSourceFiles_MultiSegmentIgnore(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src", "vendor"), 0o755))
	writeFile(t, dir, ".dispatchignore", "src/vendor\n")
	writeFile(t, filepath.Join(dir, "src"), "main.py", "print('keep')")
	writeFile(t, filepath.Join(dir, "src", "vendor"), "dep.py", "# skip")

	files := scanSourceFiles(dir, []string{".py"})
	assert.Len(t, files, 1)
	assert.Contains(t, files[0], "main.py")
}

func TestDetectEntrypoints_Procfile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Procfile", "web: gunicorn app:app")
	writeFile(t, dir, "app.py", "")

	entries := DetectEntrypoints(dir)
	assert.Contains(t, entries, "Procfile")
	assert.Contains(t, entries, "app.py")
}

func TestDetectEntrypoints_SrcDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0o755))
	writeFile(t, filepath.Join(dir, "src"), "main.py", "print('hello')")

	entries := DetectEntrypoints(dir)
	assert.Contains(t, entries, "src/main.py")
}

func TestDetectPorts_RecursiveScan(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0o755))
	writeFile(t, filepath.Join(dir, "src"), "server.py", "app.run(port=9090)")

	ports := DetectPorts(dir)
	assert.Contains(t, ports, 9090)
}

func TestDetectGPU_RecursiveScan(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "models"), 0o755))
	writeFile(t, filepath.Join(dir, "models"), "train.py", "import torch\nmodel = torch.nn.Linear(10, 1)")
	writeFile(t, dir, "requirements.txt", "numpy\n") // no torch at top level

	gpu := DetectGPURequirements(dir)
	assert.True(t, gpu.Required)
	assert.Equal(t, "pytorch", gpu.Framework)
}
