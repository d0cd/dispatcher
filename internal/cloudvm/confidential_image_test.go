package cloudvm

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

func TestAgentImageBuilder_BuildsPushesAndPinsDigest(t *testing.T) {
	var calls [][]string
	prev := buildExec
	buildExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if name == "gcloud" && contains(args, "describe") {
			return []byte("sha256:abc123\n"), nil // digest resolution
		}
		return []byte("ok"), nil
	}
	t.Cleanup(func() { buildExec = prev })

	build := NewAgentImageBuilder(ImageBuildConfig{
		Registry: "us-east1-docker.pkg.dev", Project: "proj", Repo: "dispatcher-cs", RepoRoot: t.TempDir(),
	})
	ref, digest, err := build(context.Background(), types.WorkloadSpec{})
	require.NoError(t, err)

	assert.Equal(t, "sha256:abc123", digest)
	assert.Equal(t, "us-east1-docker.pkg.dev/proj/dispatcher-cs/attest@sha256:abc123", ref,
		"the returned reference is digest-pinned — exactly what the attestation allowlists")

	// The essential sequence: build (amd64) → push → resolve digest.
	var built, pushed, described bool
	for _, c := range calls {
		joined := strings.Join(c, " ")
		if c[0] == "docker" && contains(c, "build") {
			built = true
			assert.Contains(t, joined, "linux/amd64", "CS runs amd64")
		}
		if c[0] == "docker" && contains(c, "push") {
			pushed = true
		}
		if c[0] == "gcloud" && contains(c, "describe") {
			described = true
		}
	}
	assert.True(t, built, "must docker build")
	assert.True(t, pushed, "must push to the registry")
	assert.True(t, described, "must resolve the pushed digest")
}

func TestAgentImageBuilder_SurfacesBuildFailure(t *testing.T) {
	prev := buildExec
	buildExec = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "docker" {
			return []byte("build blew up"), assertErr("exit 1")
		}
		return []byte("ok"), nil
	}
	t.Cleanup(func() { buildExec = prev })

	build := NewAgentImageBuilder(ImageBuildConfig{Registry: "r", Project: "p", Repo: "repo", RepoRoot: t.TempDir()})
	_, _, err := build(context.Background(), types.WorkloadSpec{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build blew up", "the CLI's own complaint must surface")
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
