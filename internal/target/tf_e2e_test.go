//go:build tfe2e

// Terraform e2e tests exercise FetchTerraformTargets against a real terraform/
// tofu binary. Excluded from the normal suite (build tag tfe2e) because they
// shell out to terraform. Run with:
//
//	go test -tags tfe2e -run TestTFE2E ./internal/target/
//
// They validate what the stubbed runTF tests can't: that a real
// `terraform output -json` envelope is parsed into importable targets.
package target

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireTerraform(t *testing.T) string {
	t.Helper()
	for _, b := range []string{"terraform", "tofu"} {
		if _, err := exec.LookPath(b); err == nil {
			return b
		}
	}
	t.Skip("no terraform/tofu binary on PATH")
	return ""
}

func mustRun(t *testing.T, ctx context.Context, name string, args ...string) {
	t.Helper()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	require.NoError(t, err, "%s %v failed: %s", name, args, out)
}

// A real `dispatcher_targets` output, applied and read back, must parse into the
// declared SSH target.
func TestTFE2E_OutputBecomesTarget(t *testing.T) {
	bin := requireTerraform(t)
	dir := t.TempDir()

	const tf = `
output "dispatcher_targets" {
  value = {
    targets = [{
      id   = "tf-box"
      kind = "ssh"
      ssh  = { host = "203.0.113.9", user = "ubuntu", port = 22, key_file = "" }
    }]
  }
}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o644))

	ctx := context.Background()
	mustRun(t, ctx, bin, "-chdir="+dir, "init", "-input=false", "-no-color")
	mustRun(t, ctx, bin, "-chdir="+dir, "apply", "-auto-approve", "-input=false", "-no-color")

	blob, err := FetchTerraformTargets(ctx, dir, TerraformOptions{Binary: bin})
	require.NoError(t, err)

	got, err := ParseDispatcherTargets(blob)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "tf-box", got[0].ID)
	assert.Equal(t, "203.0.113.9", got[0].SSH.Host)
	assert.True(t, got[0].Enabled)
}

// An absent dispatcher_targets output is a no-op sentinel, not a failure.
func TestTFE2E_NoOutputIsSentinel(t *testing.T) {
	bin := requireTerraform(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"),
		[]byte("output \"unrelated\" { value = \"x\" }\n"), 0o644))

	ctx := context.Background()
	mustRun(t, ctx, bin, "-chdir="+dir, "init", "-input=false", "-no-color")
	mustRun(t, ctx, bin, "-chdir="+dir, "apply", "-auto-approve", "-input=false", "-no-color")

	_, err := FetchTerraformTargets(ctx, dir, TerraformOptions{Binary: bin})
	assert.ErrorIs(t, err, ErrNoTargetsOutput)
}
