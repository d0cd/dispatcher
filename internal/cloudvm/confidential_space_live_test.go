package cloudvm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

// TestGolden_CSLiveExchange drives the FULL Phase 2 execution model against a
// live Confidential Space VM running dispatcher-attest: attest over the untrusted
// endpoint, verify the Google-signed token (signature + nonce + channel-key
// binding + image digest), seal a payload to the attested channel key, run it
// inside the TEE, and open the sealed result. Gated on the live endpoint env vars
// so CI stays offline.
//
//	DISPATCHER_CS_LIVE_ENDPOINT=http://<vm-ip>:8443 \
//	DISPATCHER_CS_LIVE_DIGEST=sha256:<attested-image-digest> \
//	go test ./internal/cloudvm -run TestGolden_CSLiveExchange -v
func TestGolden_CSLiveExchange(t *testing.T) {
	endpoint := os.Getenv("DISPATCHER_CS_LIVE_ENDPOINT")
	if endpoint == "" {
		t.Skip("set DISPATCHER_CS_LIVE_ENDPOINT (and DISPATCHER_CS_LIVE_DIGEST) to run against a live CS VM")
	}
	digest := strings.TrimSpace(os.Getenv("DISPATCHER_CS_LIVE_DIGEST"))
	require.NotEmpty(t, digest, "DISPATCHER_CS_LIVE_DIGEST is required")

	ctx := context.Background()
	keys, err := attest.LoadGoogleCSKeys(ctx)
	require.NoError(t, err, "the live Google Confidential Space JWKS must load")

	// Attest over the untrusted endpoint + verify the real token: signature (live
	// JWKS) + nonce + channel-key binding + the attested image digest on the allowlist.
	att := attest.NewCSAttester(keys, endpoint)
	res, err := att.Verify(ctx,
		types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{digest}})
	require.NoError(t, err, "the live token must verify with the channel-key binding")
	require.True(t, res.Verified, res.Verdict)
	assert.Equal(t, digest, res.Measurement)
	require.NotEmpty(t, res.ChannelKey)

	// Seal a payload to the attested key, run it inside the TEE, open the result.
	result, err := agent.RunSealedExchange(ctx, endpoint, res.ChannelKey, agent.Payload{
		Command: []string{"sh", "-c", "echo hello from TEE; echo secret=$SECRET"},
		DotEnv:  []byte("SECRET=live-sealed\n"),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, string(result.Stdout), "hello from TEE")
	assert.Contains(t, string(result.Stdout), "secret=live-sealed", "the sealed .env reached the workload inside the TEE")
}

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
