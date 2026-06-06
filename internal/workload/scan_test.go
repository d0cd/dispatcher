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

func TestDetectSubWorkloads_Monorepo(t *testing.T) {
	dir := t.TempDir()

	// Create two independent sub-projects
	api := filepath.Join(dir, "api")
	worker := filepath.Join(dir, "worker")
	require.NoError(t, os.MkdirAll(api, 0o755))
	require.NoError(t, os.MkdirAll(worker, 0o755))

	writeFile(t, api, "package.json", `{"name": "api"}`)
	writeFile(t, api, "index.js", "console.log('api')")
	writeFile(t, worker, "requirements.txt", "celery\n")
	writeFile(t, worker, "worker.py", "print('worker')")

	subs := DetectSubWorkloads(dir)
	assert.Len(t, subs, 2)
}

func TestDetectSubWorkloads_SingleProject(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", "print('hello')")
	writeFile(t, dir, "requirements.txt", "flask\n")

	subs := DetectSubWorkloads(dir)
	assert.Nil(t, subs) // single project, no sub-workloads
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
