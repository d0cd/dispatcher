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

// usesAzureConfidential reports whether a run should take the Azure confidential
// (SEV-SNP CVM, MAA-attested + sealed) path: a confidential Azure run with
// attestation on. `attestation: off` stays on the plain SSH path.
func usesAzureConfidential(p *types.Plan) bool {
	c := p.Workload.Requirements.Confidential
	return c.Required && c.Attestation != "off" && p.Recommendation != nil && p.Recommendation.Target == "azure-vm"
}

// usesAWSConfidential reports whether a run should take the AWS confidential
// (SEV-SNP, go-sev-guest-verified + sealed) path: a confidential AWS run with
// attestation on. `attestation: off` stays on the plain SSH path.
func usesAWSConfidential(p *types.Plan) bool {
	c := p.Workload.Requirements.Confidential
	return c.Required && c.Attestation != "off" && p.Recommendation != nil && p.Recommendation.Target == "aws-vm"
}

// newAWSConfidentialAdapter builds the AWS confidential adapter. Verification is
// go-sev-guest against AMD roots (no vendor keys to load); agentBin is the
// cross-compiled dispatcher-attest-aws binary. Fails closed when unconfigured.
func newAWSConfidentialAdapter(_ context.Context) (adapter.TargetAdapter, error) {
	agentBin := os.Getenv("DISPATCHER_AWS_AGENT_BIN")
	if agentBin == "" {
		return nil, fmt.Errorf("confidential AWS runs need the measured agent binary: set DISPATCHER_AWS_AGENT_BIN " +
			"to a cross-compiled dispatcher-attest-aws (GOOS=linux GOARCH=amd64)")
	}
	region := os.Getenv("DISPATCHER_AWS_REGION")
	return cloudvm.NewAWSConfidentialAdapter(
		cloudvm.NewAWSProvider(region), agentBin,
		cloudvm.Config{ProviderID: cloudvm.ProviderAWS, Region: region, SSHUser: "ubuntu"},
	), nil
}

// newAzureConfidentialAdapter builds the Azure confidential adapter: the pinned
// MAA instance's live signing keys + the cross-compiled agent binary + the Azure
// provider. Fails closed with guidance when unconfigured.
func newAzureConfidentialAdapter(ctx context.Context) (adapter.TargetAdapter, error) {
	maaURL := os.Getenv("DISPATCHER_MAA_URL")
	if maaURL == "" {
		maaURL = "https://sharedeus.eus.attest.azure.net"
	}
	agentBin := os.Getenv("DISPATCHER_AZURE_AGENT_BIN")
	if agentBin == "" {
		return nil, fmt.Errorf("confidential Azure runs need the measured agent binary: set DISPATCHER_AZURE_AGENT_BIN " +
			"to a cross-compiled dispatcher-attest-azure (GOOS=linux GOARCH=amd64)")
	}
	keys, err := cloudvm.LoadAzureMAAKeys(ctx, maaURL)
	if err != nil {
		return nil, fmt.Errorf("load MAA signing keys from %s/certs: %w", maaURL, err)
	}
	rg := os.Getenv("DISPATCHER_AZURE_RG")
	if rg == "" {
		rg = "dispatcher-rg"
	}
	location := os.Getenv("DISPATCHER_AZURE_LOCATION")
	// The MAA issuer is the instance URL (the token's iss).
	return cloudvm.NewAzureConfidentialAdapter(
		cloudvm.NewAzureProvider(rg, location),
		keys, maaURL, maaURL, agentBin,
		cloudvm.Config{ProviderID: cloudvm.ProviderAzure, Region: location, SSHUser: "dispatcher"},
	), nil
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
