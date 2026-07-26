package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/target"
)

// TestMain disables the live pricing fetch for the whole CLI test suite.
// Without this, every plan/run/audit/diagnose test would hit the real public
// AWS/Azure pricing endpoints, gating CI on outbound network and adding tens
// of seconds per test. Production callers still get live pricing.
func TestMain(m *testing.M) {
	_ = os.Setenv("DISPATCHER_DISABLE_LIVE_PRICING", "1")
	os.Exit(m.Run())
}

// executeCommand runs a CLI command and captures stdout/stderr.
func executeCommand(args ...string) (string, string, error) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	rootCmd.SetArgs(args)

	err := rootCmd.Execute()

	// Reset for next call. Persistent flags retain their parsed values across
	// Execute calls, so reset the globals too — otherwise e.g. `--json` from one
	// test leaks into the next and silently changes its output format.
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	rootCmd.SetArgs(nil)
	rootFlags.output = "text"
	rootFlags.json = false
	rootFlags.stateDir = ""
	rootFlags.noColor = false
	importFlags.fromJSON = ""
	importFlags.fromTerraform = ""
	importFlags.binary = ""
	importFlags.workspace = ""
	importFlags.allowSensitive = false
	importFlags.strict = false
	importFlags.yes = false
	importFlags.dryRun = false

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

func TestCLI_TargetsDoctor_NotFoundListsAvailable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, _, err := executeCommand("targets", "doctor", "no-such-target-xyz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no-such-target-xyz")
	assert.Contains(t, err.Error(), "available targets:")
	// A known builtin should be listed so the user can correct a typo.
	assert.Contains(t, err.Error(), "local-docker")
}

func TestCLI_TargetsImport_FromJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	jf := filepath.Join(t.TempDir(), "t.json")
	require.NoError(t, os.WriteFile(jf,
		[]byte(`{"targets":[{"id":"byo","kind":"ssh","ssh":{"host":"h.example","user":"ubuntu"}}]}`), 0o644))

	_, _, err := executeCommand("targets", "import", "--from-json", jf, "--yes")
	require.NoError(t, err)

	r := target.NewRegistry()
	require.NoError(t, r.LoadUserConfig())
	tc, ok := r.Get("byo")
	require.True(t, ok)
	assert.True(t, tc.Enabled)
	require.NotNil(t, tc.SSH)
	assert.Equal(t, "h.example", tc.SSH.Host)
}

func TestCLI_TargetsImport_AbortsWithoutYes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	jf := filepath.Join(t.TempDir(), "t.json")
	require.NoError(t, os.WriteFile(jf,
		[]byte(`{"targets":[{"id":"byo","kind":"ssh","ssh":{"host":"h.example"}}]}`), 0o644))

	// No --yes and a non-terminal stdin → the prompt reads EOF and aborts.
	_, _, err := executeCommand("targets", "import", "--from-json", jf)
	require.NoError(t, err)

	r := target.NewRegistry()
	require.NoError(t, r.LoadUserConfig())
	_, ok := r.Get("byo")
	assert.False(t, ok, "import must not persist without confirmation")
}

func TestCLI_TargetsImport_StrictRejectsMissingKeyFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	jf := filepath.Join(t.TempDir(), "t.json")
	require.NoError(t, os.WriteFile(jf,
		[]byte(`{"targets":[{"id":"byo","kind":"ssh","ssh":{"host":"h.example","key_file":"/no/such/key"}}]}`), 0o644))

	_, _, err := executeCommand("targets", "import", "--from-json", jf, "--yes", "--strict")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "strict")

	// Without --strict it warns but imports.
	_, _, err = executeCommand("targets", "import", "--from-json", jf, "--yes")
	require.NoError(t, err)
	r := target.NewRegistry()
	require.NoError(t, r.LoadUserConfig())
	_, ok := r.Get("byo")
	assert.True(t, ok)
}

func TestCLI_TargetsImport_DryRunWritesNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	jf := filepath.Join(t.TempDir(), "t.json")
	require.NoError(t, os.WriteFile(jf,
		[]byte(`{"targets":[{"id":"byo","kind":"ssh","ssh":{"host":"h.example"}}]}`), 0o644))

	_, _, err := executeCommand("targets", "import", "--from-json", jf, "--dry-run")
	require.NoError(t, err)

	r := target.NewRegistry()
	require.NoError(t, r.LoadUserConfig())
	_, ok := r.Get("byo")
	assert.False(t, ok, "--dry-run must not persist anything")
}

func TestCLI_TargetsAdd_KeyFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, _, err := executeCommand("targets", "add", "box",
		"--kind", "ssh", "--host", "h.example", "--key-file", "/tmp/k")
	require.NoError(t, err)

	r := target.NewRegistry()
	require.NoError(t, r.LoadUserConfig())
	tc, ok := r.Get("box")
	require.True(t, ok)
	require.NotNil(t, tc.SSH)
	assert.Equal(t, "/tmp/k", tc.SSH.KeyFile)
}

// A custom cloud-vm target can never be executed (only the built-in *-vm targets
// resolve a provider adapter), so `targets add --kind cloud-vm` must be rejected
// at add time rather than silently creating an unrunnable target.
func TestCLI_TargetsAdd_RejectsCloudVM(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, _, err := executeCommand("targets", "add", "my-cloud", "--kind", "cloud-vm")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloud-vm")

	r := target.NewRegistry()
	require.NoError(t, r.LoadUserConfig())
	_, ok := r.Get("my-cloud")
	assert.False(t, ok, "the unrunnable cloud-vm target must not be persisted")
}

func TestCLI_TargetsRemove(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, _, err := executeCommand("targets", "add", "tmp-box", "--kind", "docker")
	require.NoError(t, err)

	_, _, err = executeCommand("targets", "remove", "tmp-box")
	require.NoError(t, err)

	// Removing again must fail — the file is gone.
	_, _, err = executeCommand("targets", "remove", "tmp-box")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tmp-box")
}

func TestCLI_Validate_Valid(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dispatcher.yaml"),
		[]byte("name: demo\nmaxCost: 5\nmaxTime: 1h\n"), 0o644))
	_, _, err := executeCommand("validate", dir)
	require.NoError(t, err)
}

func TestCLI_Validate_Invalid(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dispatcher.yaml"),
		[]byte("name: demo\nmaxTime: not-a-duration\n"), 0o644))
	_, _, err := executeCommand("validate", dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maxTime")
}

func TestCLI_Validate_NoConfig(t *testing.T) {
	dir := t.TempDir()
	_, _, err := executeCommand("validate", dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no dispatcher.yaml")
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
	assert.FileExists(t, filepath.Join(dir, "dispatcher.yaml"))

	content, err := os.ReadFile(filepath.Join(dir, "dispatcher.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "name:")
	assert.Contains(t, string(content), "command:")
}

func TestCLI_Init_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`print("hello")`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dispatcher.yaml"), []byte("existing"), 0o644))

	_, _, err := executeCommand("init", dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestCLI_Init_Force(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`print("hello")`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dispatcher.yaml"), []byte("old"), 0o644))

	_, _, err := executeCommand("init", dir, "--force")
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(dir, "dispatcher.yaml"))
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

// --allow-ssh-from must be accepted for every target whose provider implements a
// per-run SSH firewall (Hetzner and AWS), and rejected for the rest — so an AWS
// user isn't wrongly told a working feature is unsupported.
func TestPerRunFirewallSupported(t *testing.T) {
	for _, target := range []string{"hetzner-vm", "aws-vm", "gcp-vm", "azure-vm"} {
		assert.True(t, perRunFirewallSupported(target), "%s implements a per-run SSH firewall", target)
	}
	for _, target := range []string{"local-docker", "kubernetes", "lima-vm"} {
		assert.False(t, perRunFirewallSupported(target), "%s has no per-run SSH firewall", target)
	}
}
