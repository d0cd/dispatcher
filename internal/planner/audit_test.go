package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeAuditFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		full := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o644))
	}
	return dir
}

// Helper: find a finding by category. Returns nil if none.
func findByCategory(findings []AuditFinding, cat string) *AuditFinding {
	for i := range findings {
		if findings[i].Category == cat {
			return &findings[i]
		}
	}
	return nil
}

// Helper: count findings by category.
func countByCategory(findings []AuditFinding, cat string) int {
	n := 0
	for _, f := range findings {
		if f.Category == cat {
			n++
		}
	}
	return n
}

func TestDeterministicAudit_CleanScript(t *testing.T) {
	tools, _ := setupTestEnv(t)
	dir := writeAuditFixture(t, map[string]string{
		"main.py":          "print('hi')",
		"requirements.txt": "requests\n",
	})

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicAudit(context.Background(), dir)
	require.NoError(t, err)

	// Plain script with no secrets and no GPU: expect a clean verdict.
	assert.Equal(t, "ready", res.Verdict)
	assert.Empty(t, res.Findings)
}

func TestDeterministicAudit_ServiceMissingDockerfile(t *testing.T) {
	tools, _ := setupTestEnv(t)
	dir := writeAuditFixture(t, map[string]string{
		"app.py": "from flask import Flask\napp = Flask(__name__)\napp.run(port=8080)",
		"dispatcher.yaml": `name: my-svc
service:
  port: 8080
`,
	})

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicAudit(context.Background(), dir)
	require.NoError(t, err)

	// Service workloads should at least produce a cost-info note (long-running).
	// They may also produce a reliability warning if no Dockerfile was detected.
	costFinding := findByCategory(res.Findings, "cost")
	require.NotNil(t, costFinding, "service workloads should surface a cost info finding")
	assert.Equal(t, "info", costFinding.Severity)
}

func TestDeterministicAudit_GPUWorkloadFlaggedAsCost(t *testing.T) {
	tools, _ := setupTestEnv(t)
	dir := writeAuditFixture(t, map[string]string{
		"requirements.txt": "torch\n",
		"train.py":         "import torch\n",
	})

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicAudit(context.Background(), dir)
	require.NoError(t, err)

	// GPU jobs should at least produce one warning-severity cost finding.
	var gotGPUCost bool
	for _, f := range res.Findings {
		if f.Category == "cost" && f.Severity == "warning" {
			gotGPUCost = true
			assert.Contains(t, f.Title, "GPU")
		}
	}
	assert.True(t, gotGPUCost, "GPU job should surface a cost warning")
}

func TestDeterministicAudit_SecretsWithoutEnv(t *testing.T) {
	tools, _ := setupTestEnv(t)
	// DetectSecrets scans .env.example for declared keys; no .env supplies them.
	dir := writeAuditFixture(t, map[string]string{
		"main.py":      "print('hi')",
		".env.example": "API_KEY=\nDATABASE_URL=\n",
	})

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicAudit(context.Background(), dir)
	require.NoError(t, err)

	// Declared but unset secret keys should trigger the secrets warning.
	secretsFinding := findByCategory(res.Findings, "secrets")
	require.NotNil(t, secretsFinding, "missing secret values should surface a secrets warning")
	assert.Equal(t, "warning", secretsFinding.Severity)

	// And the compliance info finding (about cloud approval requirements).
	complianceFinding := findByCategory(res.Findings, "compliance")
	require.NotNil(t, complianceFinding, "secrets should surface a compliance finding")
	assert.Equal(t, "info", complianceFinding.Severity)
}

func TestDeterministicAudit_SecretsWithEnvDropsSecretsFinding(t *testing.T) {
	tools, _ := setupTestEnv(t)
	dir := writeAuditFixture(t, map[string]string{
		"main.py":      "print('hi')",
		".env.example": "API_KEY=\n",
		".env":         "API_KEY=secretvalue\n",
	})

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicAudit(context.Background(), dir)
	require.NoError(t, err)

	// Configured secrets should not raise a 'secrets' finding. The
	// compliance info finding still fires (it's about runtime, not config).
	assert.Equal(t, 0, countByCategory(res.Findings, "secrets"),
		"configured secrets should not raise a secrets finding")
}

func TestDeterministicAudit_VerdictPropagation(t *testing.T) {
	// Construct findings of each severity and verify verdict rules.
	cases := []struct {
		name     string
		findings []AuditFinding
		verdict  string
	}{
		{name: "empty", findings: nil, verdict: "ready"},
		{name: "info only", findings: []AuditFinding{{Severity: "info"}}, verdict: "ready"},
		{name: "warning bumps to concerns", findings: []AuditFinding{{Severity: "warning"}}, verdict: "concerns"},
		{name: "critical blocks", findings: []AuditFinding{{Severity: "critical"}, {Severity: "warning"}}, verdict: "blocked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.verdict, verdictFromFindings(c.findings))
		})
	}
}

func TestDeterministicAudit_FindingsSortedBySeverity(t *testing.T) {
	tools, _ := setupTestEnv(t)
	dir := writeAuditFixture(t, map[string]string{
		"main.py":          "import os; print(os.environ['MISSING_KEY'])",
		"requirements.txt": "torch\n",
	})

	p := NewPlanner(nil, tools)
	res, err := p.DeterministicAudit(context.Background(), dir)
	require.NoError(t, err)

	// First finding should have rank <= last finding.
	for i := 1; i < len(res.Findings); i++ {
		prev := severityRank(res.Findings[i-1].Severity)
		curr := severityRank(res.Findings[i].Severity)
		assert.LessOrEqual(t, prev, curr,
			"finding %d (sev=%s) should not be ordered after finding %d (sev=%s)",
			i-1, res.Findings[i-1].Severity, i, res.Findings[i].Severity)
	}
}

func TestDeterministicAudit_RejectsEmptyPath(t *testing.T) {
	tools, _ := setupTestEnv(t)
	p := NewPlanner(nil, tools)
	_, err := p.DeterministicAudit(context.Background(), "")
	assert.Error(t, err)
}

// --- Structured-output parsing -------------------------------------------------

func TestMergeAuditStructured_PlainJSON(t *testing.T) {
	res := &AuditResult{}
	ok := mergeAuditStructured(res, `{"summary":"all good","verdict":"ready","findings":[]}`)
	assert.True(t, ok)
	assert.Equal(t, "all good", res.Summary)
	assert.Equal(t, "ready", res.Verdict)
}

func TestMergeAuditStructured_JSONInMarkdownFence(t *testing.T) {
	// LLMs sometimes wrap JSON in markdown despite the prompt.
	content := "```json\n" +
		`{"summary":"wrapped","verdict":"concerns","findings":[{"severity":"warning","category":"cost","title":"x"}]}` +
		"\n```"
	res := &AuditResult{}
	ok := mergeAuditStructured(res, content)
	require.True(t, ok)
	assert.Equal(t, "wrapped", res.Summary)
	assert.Equal(t, "concerns", res.Verdict)
	require.Len(t, res.Findings, 1)
}

func TestMergeAuditStructured_PlainFenceWithoutLanguage(t *testing.T) {
	content := "```\n" + `{"summary":"plain fence","verdict":"ready"}` + "\n```"
	res := &AuditResult{}
	ok := mergeAuditStructured(res, content)
	require.True(t, ok)
	assert.Equal(t, "plain fence", res.Summary)
}

func TestMergeAuditStructured_PoseBailsOut(t *testing.T) {
	res := &AuditResult{}
	ok := mergeAuditStructured(res, "this is just prose, no JSON.")
	assert.False(t, ok, "non-JSON input should not be reported as parsed")
	assert.Empty(t, res.Summary)
	assert.Empty(t, res.Verdict)
	assert.Empty(t, res.Findings)
}

// TestMergeAuditStructured_WrongSchemaBailsOut covers a real bug: the LLM
// sometimes returns JSON that happens to decode without error but doesn't
// contain any audit-shaped fields (typically because it echoed a tool result
// like the workload spec). Treat that as "not parsed" so the caller surfaces
// it as an unknown verdict instead of silently saying "ready".
func TestMergeAuditStructured_WrongSchemaBailsOut(t *testing.T) {
	// Looks like an inspect_workload result — same package, different keys.
	wrongShape := `{"name":"my-app","detectedKind":"gpu-job","runtime":"python"}`
	res := &AuditResult{}
	ok := mergeAuditStructured(res, wrongShape)
	assert.False(t, ok, "JSON for the wrong schema should not be reported as parsed")
	assert.Empty(t, res.Summary)
	assert.Empty(t, res.Verdict)
	assert.Empty(t, res.Findings)
}

func TestStripMarkdownFence_NoFenceUnchanged(t *testing.T) {
	in := `{"summary":"raw json"}`
	assert.Equal(t, in, stripMarkdownFence(in))
}

func TestStripMarkdownFence_DanglingOpeningFence(t *testing.T) {
	// Opening fence but no newline / no closing — pass through, parser will fail.
	in := "```{not really fenced}"
	assert.Equal(t, in, stripMarkdownFence(in))
}
