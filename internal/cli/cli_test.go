package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// executeCommand runs a CLI command and captures stdout/stderr.
func executeCommand(args ...string) (string, string, error) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	rootCmd.SetArgs(args)

	err := rootCmd.Execute()

	// Reset for next call
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	rootCmd.SetArgs(nil)

	return stdout.String(), stderr.String(), err
}

func TestCLI_Help(t *testing.T) {
	out, _, err := executeCommand("--help")
	require.NoError(t, err)
	assert.Contains(t, out, "dispatcher")
	assert.Contains(t, out, "plan")
	assert.Contains(t, out, "run")
	assert.Contains(t, out, "targets")
}

func TestCLI_TargetsList(t *testing.T) {
	_, _, err := executeCommand("targets", "list")
	require.NoError(t, err)
	// Output goes to os.Stdout directly; we verify no error.
}

func TestCLI_Plan(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`print("hello")`), 0o644))

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	_, _, err := executeCommand("plan", dir)
	require.NoError(t, err)
	// Output goes to color.Output (os.Stdout) directly; we verify no error.
}

func TestCLI_Plan_InvalidPath(t *testing.T) {
	_, _, err := executeCommand("plan", "/nonexistent/path")
	assert.Error(t, err)
}

func TestCLI_Plan_WithTarget(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM python:3.11\nCMD python"), 0o644))

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	_, _, err := executeCommand("plan", dir, "--target", "local-docker")
	require.NoError(t, err)
}

func TestCLI_Plan_TargetNotFound(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`print("hello")`), 0o644))

	_, _, err := executeCommand("plan", dir, "--target", "nonexistent")
	assert.Error(t, err)
}

func TestCLI_Init(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`print("hello")`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask\n"), 0o644))

	_, _, err := executeCommand("init", dir)
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(dir, "dispatch.yaml"))

	content, err := os.ReadFile(filepath.Join(dir, "dispatch.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "name:")
	assert.Contains(t, string(content), "command:")
}

func TestCLI_Init_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`print("hello")`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dispatch.yaml"), []byte("existing"), 0o644))

	_, _, err := executeCommand("init", dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestCLI_Init_Force(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`print("hello")`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dispatch.yaml"), []byte("old"), 0o644))

	_, _, err := executeCommand("init", dir, "--force")
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(dir, "dispatch.yaml"))
	require.NoError(t, err)
	assert.NotEqual(t, "old", string(content))
}

func TestCLI_List_Empty(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	_, _, err := executeCommand("list")
	require.NoError(t, err)
}

func TestCLI_Status_NotFound(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	_, _, err := executeCommand("status", "nonexistent_run")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCLI_Explain_NotFound(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	_, _, err := executeCommand("explain", "nonexistent_plan")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCLI_Stop_NotFound(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	_, _, err := executeCommand("stop", "nonexistent_run")
	assert.Error(t, err)
}

func TestCLI_GC_DryRun(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// GC with no providers should warn but not error
	_, _, err := executeCommand("gc", "--dry-run")
	require.NoError(t, err)
}
