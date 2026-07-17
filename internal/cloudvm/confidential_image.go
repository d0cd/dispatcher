package cloudvm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/d0cd/dispatcher/internal/types"
)

// buildExec is the seam for image-build shell commands (docker/gcloud), so the
// build/push/pin sequence is unit-testable without a container runtime.
var buildExec = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// ImageBuildConfig configures the Confidential Space agent image build.
type ImageBuildConfig struct {
	Registry string // e.g. us-east1-docker.pkg.dev
	Project  string
	Repo     string // Artifact Registry repository name
	RepoRoot string // dispatcher source root (the docker build context)
}

// agentDockerfile builds dispatcher-attest from source (so no host cross-compile)
// and ships it on a slim base. The measured identity is this image's digest; the
// workload source + secrets arrive sealed at runtime, so they are never baked in.
// NOTE (MVP): the base carries only a shell — workloads needing a language runtime
// require a base that includes it; a per-runtime base image is deferred debt.
const agentDockerfile = `FROM golang:1.25 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /dispatcher-attest ./cmd/dispatcher-attest
FROM debian:stable-slim
COPY --from=build /dispatcher-attest /dispatcher-attest
LABEL "tee.launch_policy.log_redirect"="always"
EXPOSE 8443
ENTRYPOINT ["/dispatcher-attest", "--addr=:8443"]
`

// NewAgentImageBuilder returns a buildImage function (the ConfidentialSpaceAdapter
// seam) that builds the measured agent image, pushes it to Artifact Registry, and
// returns a digest-pinned reference — exactly what the attestation allowlists.
func NewAgentImageBuilder(cfg ImageBuildConfig) func(context.Context, types.WorkloadSpec) (string, string, error) {
	return func(ctx context.Context, _ types.WorkloadSpec) (string, string, error) {
		return buildAndPushAgentImage(ctx, cfg)
	}
}

func buildAndPushAgentImage(ctx context.Context, cfg ImageBuildConfig) (string, string, error) {
	repoPath := fmt.Sprintf("%s/%s/%s", cfg.Registry, cfg.Project, cfg.Repo)
	tagged := repoPath + "/attest:agent"

	// Ensure the Artifact Registry repo exists (idempotent; a describe failure
	// means create).
	if _, err := buildExec(ctx, "gcloud", "artifacts", "repositories", "describe", cfg.Repo,
		"--location", arLocation(cfg.Registry), "--project", cfg.Project, "--format", "value(name)"); err != nil {
		if out, cerr := buildExec(ctx, "gcloud", "artifacts", "repositories", "create", cfg.Repo,
			"--repository-format=docker", "--location", arLocation(cfg.Registry), "--project", cfg.Project, "--quiet"); cerr != nil {
			return "", "", fmt.Errorf("ensure artifact registry repo: %s: %w", strings.TrimSpace(string(out)), cerr)
		}
	}

	// Write the Dockerfile INSIDE the build context: some daemons (orbstack)
	// can't read a Dockerfile from a temp dir outside the context (xattr denied).
	dockerfile, err := os.CreateTemp(cfg.RepoRoot, ".dispatcher-attest-*.Dockerfile")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(dockerfile.Name())
	if _, err := dockerfile.WriteString(agentDockerfile); err != nil {
		return "", "", err
	}
	_ = dockerfile.Close()

	if out, err := buildExec(ctx, "docker", "build", "--platform", "linux/amd64",
		"-t", tagged, "-f", dockerfile.Name(), cfg.RepoRoot); err != nil {
		return "", "", fmt.Errorf("docker build: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if out, err := buildExec(ctx, "docker", "push", tagged); err != nil {
		return "", "", fmt.Errorf("docker push: %s: %w", strings.TrimSpace(string(out)), err)
	}

	out, err := buildExec(ctx, "gcloud", "artifacts", "docker", "images", "describe", tagged,
		"--format", "value(image_summary.digest)", "--project", cfg.Project)
	if err != nil {
		return "", "", fmt.Errorf("resolve pushed digest: %s: %w", strings.TrimSpace(string(out)), err)
	}
	digest := strings.TrimSpace(string(out))
	if !strings.HasPrefix(digest, "sha256:") {
		return "", "", fmt.Errorf("unexpected image digest %q", digest)
	}
	return repoPath + "/attest@" + digest, digest, nil
}

// arLocation extracts the Artifact Registry location from a registry host like
// "us-east1-docker.pkg.dev" -> "us-east1".
func arLocation(registry string) string {
	return strings.TrimSuffix(registry, "-docker.pkg.dev")
}
