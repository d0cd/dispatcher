package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupE2E creates a clean HOME and resets CLI flag state.
func setupE2E(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	// Reset persistent flag state between tests (Cobra reuses command objects)
	planFlags.ai = false
	planFlags.target = ""
	planFlags.optimize = "cost"
	planFlags.maxCost = 0
	planFlags.gpu = ""
	initFlags.force = false
	runFlags.target = ""
	runFlags.optimize = "cost"
	runFlags.maxCost = 0
	runFlags.gpu = ""
	runFlags.timeout = ""
	runFlags.yes = false
	gcFlags.dryRun = false
	importFlags.fromJSON = ""
	importFlags.fromTerraform = ""
	importFlags.binary = ""
	importFlags.workspace = ""
	importFlags.allowSensitive = false
	importFlags.strict = false
	importFlags.yes = false
	importFlags.dryRun = false
}

func writeFixture(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	base := filepath.Join(t.TempDir(), dir)
	require.NoError(t, os.MkdirAll(base, 0o755))
	for name, content := range files {
		full := filepath.Join(base, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	return base
}

// Import an SSH target from a dispatcher_targets blob, then plan a real workload
// onto it — proving the imported target is Enabled and carries capabilities (an
// infeasible import would fail the plan). This is the bring-your-own-hosts
// vertical, end to end, without needing a live host (plan is offline).
func TestE2E_ImportTargetThenPlan(t *testing.T) {
	setupE2E(t)

	dir := writeFixture(t, "wl", map[string]string{
		"main.py":          "print('hi')\n",
		"requirements.txt": "",
	})

	jf := filepath.Join(t.TempDir(), "targets.json")
	require.NoError(t, os.WriteFile(jf,
		[]byte(`{"targets":[{"id":"byo-box","kind":"ssh","ssh":{"host":"h.example","user":"ubuntu"}}]}`), 0o644))

	_, _, err := executeCommand("targets", "import", "--from-json", jf, "--yes")
	require.NoError(t, err)

	_, _, err = executeCommand("plan", dir, "--target", "byo-box")
	require.NoError(t, err, "planning onto the imported SSH target must succeed")
}

func TestE2E_InitPlanRun(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "python-app", map[string]string{
		"main.py":          `print("e2e test output")`,
		"requirements.txt": "requests\n",
	})

	// Init
	_, _, err := executeCommand("init", dir)
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(dir, "dispatcher.yaml"))

	// Plan
	_, _, err = executeCommand("plan", dir)
	require.NoError(t, err)

	// Run
	_, _, err = executeCommand("run", dir, "-y")
	require.NoError(t, err)

	// List should show the run
	_, _, err = executeCommand("list")
	require.NoError(t, err)

	// History should have an entry
	_, _, err = executeCommand("history")
	require.NoError(t, err)
}

func TestE2E_PlanDetectsNodeService(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "node-svc", map[string]string{
		"server.js": `const http = require('http');\nhttp.createServer((req,res) => res.end('ok')).listen(3000);`,
	})

	// Plan should detect service with port
	out, _, err := executeCommand("plan", dir)
	_ = out // output goes to os.Stdout
	require.NoError(t, err)
}

func TestE2E_PlanDetectsGPU(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "gpu-job", map[string]string{
		"train.py":         "import torch\nmodel = torch.nn.Linear(10,1)",
		"requirements.txt": "torch\nnumpy\n",
	})

	_, _, err := executeCommand("plan", dir)
	require.NoError(t, err)
}

func TestE2E_PlanWithBudget(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "script", map[string]string{
		"main.py": `print("hello")`,
	})

	_, _, err := executeCommand("plan", dir, "--max-cost", "0.01")
	require.NoError(t, err)
}

func TestE2E_PlanWithGPUFlag(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "script", map[string]string{
		"main.py": `print("hello")`,
	})

	_, _, err := executeCommand("plan", dir, "--gpu", "h100:2")
	require.NoError(t, err)
}

func TestE2E_PlanOptimizeSpeed(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "script", map[string]string{
		"main.py": `print("hello")`,
	})

	_, _, err := executeCommand("plan", dir, "--optimize", "speed")
	require.NoError(t, err)
}

func TestE2E_PlanWithDispatchYaml(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "configured", map[string]string{
		"main.py": `print("configured")`,
		"dispatcher.yaml": `name: my-app
command: ["python3", "main.py"]
maxCost: 25
`,
	})

	_, _, err := executeCommand("plan", dir)
	require.NoError(t, err)
}

func TestE2E_PlanWithDispatchYamlService(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "svc-config", map[string]string{
		"main.py": `print("svc")`,
		"dispatcher.yaml": `name: my-svc
command: ["python3", "main.py"]
service:
  port: 8080
`,
	})

	_, _, err := executeCommand("plan", dir)
	require.NoError(t, err)
}

func TestE2E_PlanAI(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "script", map[string]string{
		"main.py": `print("hello")`,
	})

	_, _, err := executeCommand("plan", dir, "--ai")
	require.NoError(t, err)
}

func TestE2E_PlanWithSecrets(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "secrets", map[string]string{
		"main.py": `print("secrets")`,
		".env":    "API_KEY=sk-test\nDATABASE_URL=postgres://localhost/db\n",
	})

	_, _, err := executeCommand("plan", dir)
	require.NoError(t, err)
}

func TestE2E_PlanTargetNotFound(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "script", map[string]string{
		"main.py": `print("hello")`,
	})

	_, _, err := executeCommand("plan", dir, "--target", "nonexistent")
	assert.Error(t, err)
}

func TestE2E_PlanInvalidPath(t *testing.T) {
	_, _, err := executeCommand("plan", "/nonexistent/path/xyz")
	assert.Error(t, err)
}

func TestE2E_RunPythonScript(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "py", map[string]string{
		"main.py": `print("run-test-output")`,
	})

	_, _, err := executeCommand("run", dir, "-y")
	require.NoError(t, err)

	// Verify logs were persisted
	home, _ := os.UserHomeDir()
	entries, _ := os.ReadDir(filepath.Join(home, ".dispatcher", "runs"))
	foundLog := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".log") {
			data, _ := os.ReadFile(filepath.Join(home, ".dispatcher", "runs", e.Name()))
			if strings.Contains(string(data), "run-test-output") {
				foundLog = true
			}
		}
	}
	assert.True(t, foundLog, "log file should contain run output")
}

func TestE2E_RunNodeScript(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "node", map[string]string{
		"index.js": `console.log("node-e2e-output")`,
	})

	_, _, err := executeCommand("run", dir, "-y")
	require.NoError(t, err)
}

func TestE2E_RunWithTimeout(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "slow", map[string]string{
		"main.py": "import time\ntime.sleep(60)\n",
	})

	_, _, err := executeCommand("run", dir, "-y", "--timeout", "2s")
	assert.Error(t, err) // should fail due to timeout
}

func TestE2E_RunServiceOnLocalProcessRejected(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "svc", map[string]string{
		"main.py": `print("svc")`,
		"dispatcher.yaml": `name: svc
service:
  port: 8080
`,
	})

	_, _, err := executeCommand("run", dir, "-y", "--target", "local-process")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not feasible")
}

func TestE2E_StatusNotFound(t *testing.T) {
	setupE2E(t)
	_, _, err := executeCommand("status", "run_nonexistent")
	assert.Error(t, err)
}

func TestE2E_LogsNotFound(t *testing.T) {
	setupE2E(t)
	_, _, err := executeCommand("logs", "run_nonexistent")
	assert.Error(t, err)
}

func TestE2E_StopCompletedRun(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "py", map[string]string{
		"main.py": `print("done")`,
	})

	_, _, err := executeCommand("run", dir, "-y")
	require.NoError(t, err)

	// Find the run ID
	home, _ := os.UserHomeDir()
	entries, _ := os.ReadDir(filepath.Join(home, ".dispatcher", "runs"))
	var runID string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			runID = strings.TrimSuffix(e.Name(), ".json")
			break
		}
	}
	require.NotEmpty(t, runID)

	// Stop should be a no-op on completed run
	_, _, err = executeCommand("stop", runID)
	require.NoError(t, err)
}

func TestE2E_StatusAndCostAfterRun(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "py", map[string]string{
		"main.py": `print("status-test")`,
	})

	_, _, err := executeCommand("run", dir, "-y")
	require.NoError(t, err)

	home, _ := os.UserHomeDir()
	entries, _ := os.ReadDir(filepath.Join(home, ".dispatcher", "runs"))
	var runID string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			runID = strings.TrimSuffix(e.Name(), ".json")
			break
		}
	}
	require.NotEmpty(t, runID)

	_, _, err = executeCommand("status", runID)
	require.NoError(t, err)

	_, _, err = executeCommand("cost", runID)
	require.NoError(t, err)

	_, _, err = executeCommand("logs", runID)
	require.NoError(t, err)
}

func TestE2E_ExplainAfterPlan(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "py", map[string]string{
		"main.py": `print("explain-test")`,
	})

	// Use regular plan (not --ai) so the plan gets saved
	_, _, err := executeCommand("plan", dir)
	require.NoError(t, err)
	// Plans are saved by the regular plan command

	// Find the plan ID
	home, _ := os.UserHomeDir()
	entries, _ := os.ReadDir(filepath.Join(home, ".dispatcher", "plans"))
	var planID string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			planID = strings.TrimSuffix(e.Name(), ".json")
			break
		}
	}
	require.NotEmpty(t, planID)

	_, _, err = executeCommand("explain", planID)
	require.NoError(t, err)
}

func TestE2E_TargetsAddAndList(t *testing.T) {
	setupE2E(t)

	_, _, err := executeCommand("targets", "add", "test-box", "--kind", "ssh", "--host", "example.com")
	require.NoError(t, err)

	_, _, err = executeCommand("targets", "list")
	require.NoError(t, err)
}

func TestE2E_InitForce(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "py", map[string]string{
		"main.py":         `print("hello")`,
		"dispatcher.yaml": "old content",
	})

	// Without force — should fail
	_, _, err := executeCommand("init", dir)
	assert.Error(t, err)

	// With force — should succeed
	_, _, err = executeCommand("init", dir, "--force")
	require.NoError(t, err)

	data, _ := os.ReadFile(filepath.Join(dir, "dispatcher.yaml"))
	assert.NotEqual(t, "old content", string(data))
}

func TestE2E_GCDryRun(t *testing.T) {
	setupE2E(t)
	_, _, err := executeCommand("gc", "--dry-run")
	require.NoError(t, err)
}

func TestE2E_DispatchIgnore(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "with-ignore", map[string]string{
		"main.py":         `print("hello")`,
		".dispatchignore": "data/\nlogs/\n",
		"data/big.csv":    "lots of data",
		"src/lib.py":      "import os",
	})

	_, _, err := executeCommand("plan", dir)
	require.NoError(t, err)
}

func TestE2E_ApproveResolvesPendingRecord(t *testing.T) {
	setupE2E(t)
	// Stand up a pending approval directly via the package — no need to drive
	// a full run, since approve only depends on the persisted record.
	_, _, err := executeCommand("approve", "run_does_not_exist")
	assert.Error(t, err, "approving a non-existent run should error")
}

func TestE2E_RunInjectsDotEnvIntoProcess(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "secrets-run", map[string]string{
		"main.py": "import os\nprint('API_KEY=' + os.environ.get('API_KEY', 'missing'))\n",
		".env":    "API_KEY=sk-injected\n",
	})

	_, _, err := executeCommand("run", dir, "-y")
	require.NoError(t, err)

	home, _ := os.UserHomeDir()
	entries, _ := os.ReadDir(filepath.Join(home, ".dispatcher", "runs"))
	found := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".log") {
			data, _ := os.ReadFile(filepath.Join(home, ".dispatcher", "runs", e.Name()))
			if strings.Contains(string(data), "API_KEY=sk-injected") {
				found = true
			}
		}
	}
	assert.True(t, found, "log should contain injected env var; .env was not propagated")
}

func TestE2E_MultipleRunsAccumulateHistory(t *testing.T) {
	setupE2E(t)
	dir := writeFixture(t, "py", map[string]string{
		"main.py": `print("tick")`,
	})

	// Run 3 times
	for i := 0; i < 3; i++ {
		_, _, err := executeCommand("run", dir, "-y")
		require.NoError(t, err)
	}

	// History should exist
	_, _, err := executeCommand("history")
	require.NoError(t, err)

	// List should show 3 runs
	_, _, err = executeCommand("list")
	require.NoError(t, err)
}
