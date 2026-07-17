package cloudvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/types"
)

// TestGolden_CSLiveAdapter exercises the FULLY INTEGRATED ConfidentialSpaceAdapter
// against real GCP: build+push the measured agent image, provision the CS VM
// (scope + secure boot + tee-image-reference) with the agent-port firewall, attest
// + verify, seal source/.env, run inside the TEE, retrieve the sealed result, and
// tear everything down. Gated on DISPATCHER_CS_LIVE_BUILD so CI stays offline.
//
//	DISPATCHER_CS_LIVE_BUILD=1 DISPATCHER_GCP_PROJECT=<p> DISPATCHER_GCP_ZONE=us-east4-a \
//	DISPATCHER_CS_REPO_ROOT=$PWD go test ./internal/cloudvm -run TestGolden_CSLiveAdapter -v -timeout 20m
func TestGolden_CSLiveAdapter(t *testing.T) {
	if os.Getenv("DISPATCHER_CS_LIVE_BUILD") == "" {
		t.Skip("set DISPATCHER_CS_LIVE_BUILD=1 (+ project/zone/repo-root) to run the integrated live path")
	}
	project := os.Getenv("DISPATCHER_GCP_PROJECT")
	require.NotEmpty(t, project, "DISPATCHER_GCP_PROJECT required")
	zone := os.Getenv("DISPATCHER_GCP_ZONE")
	if zone == "" {
		zone = "us-east4-a"
	}
	repoRoot := os.Getenv("DISPATCHER_CS_REPO_ROOT")
	require.NotEmpty(t, repoRoot, "DISPATCHER_CS_REPO_ROOT required (dispatcher source tree)")

	ctx := context.Background()
	keys, err := attest.LoadGoogleCSKeys(ctx)
	require.NoError(t, err)
	build := NewAgentImageBuilder(ImageBuildConfig{
		Registry: "us-east1-docker.pkg.dev", Project: project, Repo: "dispatcher-cs", RepoRoot: repoRoot,
	})
	a := NewConfidentialSpaceAdapter(NewGCPProvider(project, zone), keys, build,
		Config{ProviderID: ProviderGCP, Region: zone})

	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, ".env"), []byte("SECRET=integrated\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "hello.txt"), []byte("from-source\n"), 0o644))
	p := &types.Plan{
		Metadata: types.PlanMetadata{ID: "live-int"},
		Workload: types.WorkloadSpec{
			Name: "live", Source: types.WorkloadSource{Path: src},
			Command:      []string{"sh", "-c", "echo integrated=$SECRET; cat hello.txt"},
			Requirements: types.ResourceRequirements{Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp"}},
		},
	}

	h, err := a.Execute(ctx, p)
	require.NoError(t, err, "integrated confidential run must succeed")
	t.Cleanup(func() { _, _ = a.Cleanup(context.Background(), h) })

	st := h.State.(*confidentialRunState)
	assert.True(t, st.Attestation.Verified, "run must be attested")
	assert.Equal(t, 0, st.Result.ExitCode)
	assert.Contains(t, string(st.Result.Stdout), "integrated=integrated", "the sealed .env reached the TEE")
	assert.Contains(t, string(st.Result.Stdout), "from-source", "the sealed source reached the TEE")

	status, err := a.Status(ctx, h)
	require.NoError(t, err)
	assert.Equal(t, types.RunStateCompleted, status)
}
