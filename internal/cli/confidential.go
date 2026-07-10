package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/types"
)

// usesConfidentialSpace reports whether a run should take the GCP Confidential
// Space container path instead of the SSH VM path: a confidential GCP run with
// attestation on. `attestation: off` (provision a TEE without verification) stays
// on the SSH path, which is the escape hatch for the unverified case.
func usesConfidentialSpace(p *types.Plan) bool {
	c := p.Workload.Requirements.Confidential
	return c.Required && c.Attestation != "off" && p.Recommendation != nil && p.Recommendation.Target == "gcp-vm"
}

// newConfidentialSpaceAdapter builds the Confidential Space adapter for a run:
// Google's live signing keys + the measured agent image builder + the GCP
// provider. Fails closed with actionable guidance when unconfigured.
func newConfidentialSpaceAdapter(ctx context.Context) (adapter.TargetAdapter, error) {
	project := gcpProject()
	if project == "" {
		return nil, fmt.Errorf("confidential GCP runs need a project; set DISPATCHER_GCP_PROJECT or run `gcloud config set project <id>`")
	}
	keys, err := cloudvm.LoadGoogleCSKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("load Google Confidential Space signing keys: %w", err)
	}
	build, err := confidentialImageBuilder(project)
	if err != nil {
		return nil, err
	}
	return cloudvm.NewConfidentialSpaceAdapter(
		cloudvm.NewGCPProvider(project, os.Getenv("DISPATCHER_GCP_ZONE")),
		keys, build,
		cloudvm.Config{ProviderID: cloudvm.ProviderGCP, Region: os.Getenv("DISPATCHER_GCP_ZONE")},
	), nil
}

// confidentialImageBuilder resolves how the measured agent image is obtained:
// a prebuilt digest-pinned image (DISPATCHER_CS_AGENT_IMAGE) skips the build;
// otherwise it's built from the dispatcher source (DISPATCHER_CS_REPO_ROOT).
func confidentialImageBuilder(project string) (func(context.Context, types.WorkloadSpec) (string, string, error), error) {
	if ref := os.Getenv("DISPATCHER_CS_AGENT_IMAGE"); ref != "" {
		at := strings.Index(ref, "@sha256:")
		if at < 0 {
			return nil, fmt.Errorf("DISPATCHER_CS_AGENT_IMAGE must be digest-pinned (…@sha256:…), got %q", ref)
		}
		digest := ref[at+1:]
		return func(context.Context, types.WorkloadSpec) (string, string, error) { return ref, digest, nil }, nil
	}
	repoRoot := os.Getenv("DISPATCHER_CS_REPO_ROOT")
	if repoRoot == "" {
		return nil, fmt.Errorf("confidential GCP runs need the measured agent image: set DISPATCHER_CS_AGENT_IMAGE to a digest-pinned prebuilt image, " +
			"or DISPATCHER_CS_REPO_ROOT to the dispatcher source tree to build it")
	}
	registry := os.Getenv("DISPATCHER_CS_REGISTRY")
	if registry == "" {
		registry = "us-east1-docker.pkg.dev"
	}
	return cloudvm.NewAgentImageBuilder(cloudvm.ImageBuildConfig{
		Registry: registry, Project: project, Repo: "dispatcher-cs", RepoRoot: repoRoot,
	}), nil
}

// gcpProject resolves the GCP project from the environment, falling back to the
// active gcloud configuration.
func gcpProject() string {
	if p := os.Getenv("DISPATCHER_GCP_PROJECT"); p != "" {
		return p
	}
	out, err := exec.Command("gcloud", "config", "get-value", "project").Output()
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(string(out))
	if p == "(unset)" {
		return ""
	}
	return p
}
