package workload

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectPythonScript(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hello")`)
	writeFile(t, dir, "requirements.txt", "flask\nrequests\n")

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)

	assert.Equal(t, types.RuntimePython, spec.Runtime)
	assert.Equal(t, types.WorkloadKindScript, spec.DetectedKind)
	assert.Contains(t, spec.Entrypoints, "main.py")
	assert.True(t, spec.Package.BuildRequired)
	assert.Equal(t, "python:3.11-slim", spec.Package.BaseImage)
}

// TestInspectDefaultsOutputsWhenDirectoryExists verifies that an `outputs/`
// directory in the workload is picked up as a default artifact path without
// requiring a dispatcher.yaml entry. This is the data-preservation default
// — without it, users have to know about the feature to benefit from it.
func TestInspectDefaultsOutputsWhenDirectoryExists(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hi")`)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "outputs"), 0o755))

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)
	assert.Equal(t, []string{"outputs/"}, spec.Outputs,
		"existing outputs/ dir should be auto-detected")
}

func TestInspectNoDefaultOutputsWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hi")`)

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)
	assert.Empty(t, spec.Outputs, "no outputs/ dir → no auto-detection")
}

func TestInspectExplicitOutputsBeatsAutoDetect(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hi")`)
	// dispatcher.yaml specifies explicit outputs — should win over auto.
	writeFile(t, dir, "dispatcher.yaml", "outputs:\n  - results/\n  - model.bin\n")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "outputs"), 0o755))

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)
	assert.Equal(t, []string{"results/", "model.bin"}, spec.Outputs)
}

func TestInspectDockerizedService(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM python:3.11\nEXPOSE 8080\nCMD [\"python\", \"app.py\"]")
	writeFile(t, dir, "app.py", `
from flask import Flask
app = Flask(__name__)
app.run(port=8080)
`)

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)

	assert.Equal(t, types.WorkloadKindService, spec.DetectedKind)
	assert.Equal(t, "Dockerfile", spec.Package.Dockerfile)
	assert.Contains(t, spec.Ports, 8080)
}

func TestInspectGPUJob(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "train.py", `import torch\nmodel = torch.nn.Linear(10, 1)`)
	writeFile(t, dir, "requirements.txt", "torch\nnumpy\n")

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)

	assert.Equal(t, types.WorkloadKindGPUJob, spec.DetectedKind)
	assert.True(t, spec.Requirements.GPU.Required)
	assert.Equal(t, "pytorch", spec.Requirements.GPU.Framework)
}

func TestInspectGoProject(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/test\ngo 1.23\n")
	writeFile(t, dir, "main.go", `package main\nfunc main() {}`)

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)

	assert.Equal(t, types.RuntimeGo, spec.Runtime)
	assert.Contains(t, spec.Entrypoints, "main.go")
}

func TestInspectWithSecrets(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", "print('hello')")
	writeFile(t, dir, ".env", "API_KEY=secret123\nDATABASE_URL=postgres://localhost/db\n")

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)

	assert.NotEmpty(t, spec.Secrets)
	kinds := make([]string, len(spec.Secrets))
	for i, s := range spec.Secrets {
		kinds[i] = s.Kind
	}
	assert.Contains(t, kinds, "api-key")
	assert.Contains(t, kinds, "database-url")
}

func TestInspectWithDataDeps(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `
import boto3
bucket = "s3://my-dataset"
db = "postgres://db.internal/mydb"
`)

	spec, err := InspectCodebase(dir)
	require.NoError(t, err)

	assert.NotEmpty(t, spec.Data)
	kinds := make([]string, len(spec.Data))
	for i, d := range spec.Data {
		kinds[i] = d.Kind
	}
	assert.Contains(t, kinds, "s3")
	assert.Contains(t, kinds, "database")
}

func TestDetectPortsFromDockerfile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM node:20\nEXPOSE 3000\nCMD [\"node\", \"server.js\"]")

	ports := DetectPorts(dir)
	assert.Contains(t, ports, 3000)
}

func TestDetectRuntimeFallbackToExtension(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "script.rb", "puts 'hello'")

	rt := DetectRuntime(dir)
	assert.Equal(t, types.RuntimeRuby, rt)
}

func TestDetectEntrypointsGoCmd(t *testing.T) {
	dir := t.TempDir()
	cmdDir := filepath.Join(dir, "cmd", "server")
	require.NoError(t, os.MkdirAll(cmdDir, 0o755))
	writeFile(t, cmdDir, "main.go", "package main")

	entries := DetectEntrypoints(dir)
	assert.Contains(t, entries, "cmd/server/main.go")
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}
