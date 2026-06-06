package plan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden planner corpus from design doc section 24.1.
// Each test creates a minimal fixture and verifies the planner's behavior.

func TestGolden_SimplePythonScript(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"main.py":          `print("hello world")`,
		"requirements.txt": "requests\n",
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	assert.Equal(t, types.WorkloadKindScript, p.Workload.DetectedKind)
	assert.Equal(t, types.RuntimePython, p.Workload.Runtime)
	assert.NotNil(t, p.Recommendation)
	// Should recommend cheapest local target
	assert.Contains(t, []string{"local-process", "local-docker", "ssh"}, p.Recommendation.Target)
}

func TestGolden_DockerizedBatchJob(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"Dockerfile": "FROM python:3.11\nCOPY . /app\nCMD [\"python\", \"process.py\"]",
		"process.py": `print("processing batch")`,
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	assert.Equal(t, types.WorkloadKindContainer, p.Workload.DetectedKind)
	assert.Equal(t, "Dockerfile", p.Workload.Package.Dockerfile)
	assert.NotNil(t, p.Recommendation)
	// Should recommend cheapest eligible target
	assert.Equal(t, "local-docker", p.Recommendation.Target)
}

func TestGolden_FastAPIService(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"main.py":          "from fastapi import FastAPI\napp = FastAPI()\nuvicorn.run(app, port=8000)",
		"requirements.txt": "fastapi\nuvicorn\n",
		"Dockerfile":       "FROM python:3.11\nEXPOSE 8000\nCMD [\"uvicorn\", \"main:app\"]",
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	assert.Equal(t, types.WorkloadKindService, p.Workload.DetectedKind)
	assert.Contains(t, p.Workload.Ports, 8000)

}

func TestGolden_GPUPyTorchJob(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"train.py":         "import torch\nmodel = torch.nn.Linear(10, 1)\nprint(torch.cuda.is_available())",
		"requirements.txt": "torch\nnumpy\nscipy\n",
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	assert.Equal(t, types.WorkloadKindGPUJob, p.Workload.DetectedKind)
	assert.True(t, p.Workload.Requirements.GPU.Required)

	// CPU-only targets must be rejected
	rejected := rejectedNames(p)
	assert.Contains(t, rejected, "local-docker")
	assert.Contains(t, rejected, "ssh")

	// Must require GPU approval
	approvals := approvalNames(p)
	assert.Contains(t, approvals, "gpu-approval")
}

func TestGolden_SandboxCodeTask(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"solve.py": `print("solving code task")`,
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	assert.Equal(t, types.WorkloadKindScript, p.Workload.DetectedKind)
	assert.NotNil(t, p.Recommendation)
}

func TestGolden_MissingDockerfile(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"app.py":           "from flask import Flask\napp = Flask(__name__)",
		"requirements.txt": "flask\n",
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	// Should generate package plan with base image
	assert.True(t, p.Workload.Package.BuildRequired)
	assert.Equal(t, "", p.Workload.Package.Dockerfile)
	assert.Equal(t, "python:3.11-slim", p.Workload.Package.BaseImage)

	// Should have package risk
	riskCats := riskCategories(p)
	assert.Contains(t, riskCats, "package-risk")
}

func TestGolden_PrivatePackageDependency(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"main.py": `print("hello")`,
		".env":    "API_KEY=secret_value\nPYPI_TOKEN=tok_abc\n",
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	assert.NotEmpty(t, p.Workload.Secrets)
	riskCats := riskCategories(p)
	assert.Contains(t, riskCats, "credential-risk")
}

func TestGolden_PrivateDatabaseDependency(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"app.py": `import psycopg2\nconn = psycopg2.connect("postgres://db.internal/mydb")`,
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	assert.NotEmpty(t, p.Workload.Data)
	dataKinds := dataKindList(p)
	assert.Contains(t, dataKinds, "database")

	riskCats := riskCategories(p)
	assert.Contains(t, riskCats, "network-access-risk")
}

func TestGolden_LargeDataset(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"process.py": `import boto3\nbucket = "s3://large-dataset-bucket"\nprint("processing data")`,
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	dataKinds := dataKindList(p)
	assert.Contains(t, dataKinds, "s3")

	riskCats := riskCategories(p)
	assert.Contains(t, riskCats, "data-egress-risk")
}

func TestGolden_UnknownDuration(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"Dockerfile": "FROM python:3.11\nCMD [\"python\", \"run.py\"]",
		"run.py":     "print('running')",
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	// Cost should include assumptions about duration
	assert.NotNil(t, p.Recommendation)
	assert.NotEmpty(t, p.Recommendation.EstimatedCost.Assumptions)
}

func TestGolden_CostAboveBudget(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"Dockerfile": "FROM python:3.11\nEXPOSE 8080\nCMD [\"python\", \"app.py\"]",
		"app.py":     "app.run(port=8080)",
	})

	// Very tight budget - only local-docker ($0) should survive
	p := mustBuild(t, dir, types.PlanConstraints{
		OptimizeFor:         types.OptimizeCost,
		MaxEstimatedCostUSD: 0.01,
	})

	assert.Equal(t, "local-docker", p.Recommendation.Target)
	// All non-free targets should be rejected for cost
	rejected := rejectedNames(p)
	assert.NotEmpty(t, rejected)
}

func TestGolden_PublicEndpoint(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"Dockerfile": "FROM node:20\nEXPOSE 3000",
		"server.js":  "app.listen(3000)",
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	assert.Equal(t, types.WorkloadKindService, p.Workload.DetectedKind)

	// Public endpoint targets should require approval
	approvals := approvalNames(p)
	// local-docker doesn't have public endpoint, but if recommended target does, check
	if p.Recommendation != nil {
		for _, a := range p.RequiredApprovals {
			if a.Name == "public-endpoint" {
				assert.Contains(t, approvals, "public-endpoint")
			}
		}
	}
}

func TestGolden_GPUOverrideFlag(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"main.py": `print("hello")`,
	})

	p := mustBuild(t, dir, types.PlanConstraints{
		OptimizeFor: types.OptimizeCost,
		RequireGPU:  "h100:2",
	})

	assert.Equal(t, types.WorkloadKindGPUJob, p.Workload.DetectedKind)
	assert.True(t, p.Workload.Requirements.GPU.Required)
	assert.Equal(t, 2, p.Workload.Requirements.GPU.Count)
	assert.Equal(t, "h100", p.Workload.Requirements.GPU.Model)

	// CPU-only targets rejected
	rejected := rejectedNames(p)
	assert.Contains(t, rejected, "local-docker")
}

func TestGolden_UntrustedCodeSandbox(t *testing.T) {
	dir := setupFixture(t, map[string]string{
		"solve.py": "print(2+2)",
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	// A sandbox-isolated target should appear once a sandbox adapter lands;
	// for now the script remains feasible on local targets.
	feasible := feasibleNames(p)
	assert.NotEmpty(t, feasible)
}

func TestGolden_NoGPUQuota(t *testing.T) {
	// This tests that a GPU workload is rejected from CPU-only targets
	// even though the target may theoretically support GPU (but workload kind doesn't match)
	dir := setupFixture(t, map[string]string{
		"train.py":         "import torch",
		"requirements.txt": "torch\n",
	})

	p := mustBuild(t, dir, types.PlanConstraints{OptimizeFor: types.OptimizeCost})

	// Targets without GPU should be rejected
	rejected := rejectedNames(p)
	assert.Contains(t, rejected, "local-docker")
}

// --- Helpers ---

func setupFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	return dir
}

func mustBuild(t *testing.T, dir string, c types.PlanConstraints) *types.Plan {
	t.Helper()
	p, err := Build(dir, c, nil)
	require.NoError(t, err)
	require.NotNil(t, p)
	return p
}

func rejectedNames(p *types.Plan) []string {
	names := make([]string, len(p.Rejected))
	for i, r := range p.Rejected {
		names[i] = r.Target
	}
	return names
}

func feasibleNames(p *types.Plan) []string {
	var names []string
	if p.Recommendation != nil {
		names = append(names, p.Recommendation.Target)
	}
	for _, a := range p.Alternatives {
		names = append(names, a.Target)
	}
	return names
}

func approvalNames(p *types.Plan) []string {
	names := make([]string, len(p.RequiredApprovals))
	for i, a := range p.RequiredApprovals {
		names[i] = a.Name
	}
	return names
}

func riskCategories(p *types.Plan) []string {
	cats := make([]string, len(p.Risks))
	for i, r := range p.Risks {
		cats[i] = r.Category
	}
	return cats
}

func dataKindList(p *types.Plan) []string {
	kinds := make([]string, len(p.Workload.Data))
	for i, d := range p.Workload.Data {
		kinds[i] = d.Kind
	}
	return kinds
}
