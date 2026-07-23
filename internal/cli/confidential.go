package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/confidential"
	"github.com/d0cd/dispatcher/internal/types"
)

// orEnv prefers a registry-resolved value, falling back to an environment
// variable. It is how the confidential adapters read pins from the unified
// registry while staying backward-compatible with the DISPATCHER_* env vars.
func orEnv(v, env string) string {
	if v != "" {
		return v
	}
	return os.Getenv(env)
}

// usesConfidentialSpace reports whether a run should take the GCP Confidential
// Space container path instead of the SSH VM path: a confidential GCP run with
// attestation on. `attestation: off` (provision a TEE without verification) stays
// on the SSH path, which is the escape hatch for the unverified case.
func usesConfidentialSpace(p *types.Plan) bool {
	c := p.Workload.Requirements.Confidential
	return c.Required && c.Attestation != "off" && p.Recommendation != nil && p.Recommendation.Target == "gcp-vm"
}

// usesAzureSNP reports whether a confidential Azure run should take the measured
// direct SNP+vTPM path (a custom measured image, agent in PCR11), selected by
// `confidential.profile: azure-snp`. This is the Azure path that measures the
// agent; the MAA path (the standard backend) does not.
func usesAzureSNP(p *types.Plan) bool {
	c := p.Workload.Requirements.Confidential
	return c.Required && c.Attestation != "off" && c.Profile == "azure-snp" &&
		p.Recommendation != nil && p.Recommendation.Target == "azure-vm"
}

// usesAWSNitro reports whether a confidential AWS run should take the Nitro
// Enclaves path (measured enclave image), selected by `confidential.profile: nitro`.
// This is the AWS path that measures the agent; the SEV-SNP path does not.
func usesAWSNitro(p *types.Plan) bool {
	c := p.Workload.Requirements.Confidential
	return c.Required && c.Attestation != "off" && c.Profile == "nitro" &&
		p.Recommendation != nil && p.Recommendation.Target == "aws-vm"
}

// newNitroConfidentialAdapter builds the AWS Nitro Enclaves adapter from the
// pre-built, pinned enclave image: DISPATCHER_AWS_NITRO_EIF (the EIF),
// DISPATCHER_AWS_NITRO_PCR0 (its measured PCR0), and DISPATCHER_AWS_NITRO_PROXY_BIN
// (a cross-compiled dispatcher-nitro-proxy). Fails closed when unconfigured; build
// the EIF + read PCR0 with deploy/nitro/build-eif.sh.
func newNitroConfidentialAdapter(_ context.Context) (adapter.TargetAdapter, error) {
	pin := confidential.Resolve(confidential.AWSNitro)
	eif := orEnv(pin.Image, "DISPATCHER_AWS_NITRO_EIF")
	proxy := orEnv(pin.Extra["proxy"], "DISPATCHER_AWS_NITRO_PROXY_BIN")
	pcr0 := orEnv(pin.Measurement, "DISPATCHER_AWS_NITRO_PCR0")
	if eif == "" || proxy == "" || pcr0 == "" {
		return nil, fmt.Errorf("confidential AWS Nitro runs need the pinned enclave image: set DISPATCHER_AWS_NITRO_EIF, " +
			"DISPATCHER_AWS_NITRO_PROXY_BIN (a cross-compiled dispatcher-nitro-proxy), and DISPATCHER_AWS_NITRO_PCR0 " +
			"(build with deploy/nitro/build-eif.sh)")
	}
	region := os.Getenv("DISPATCHER_AWS_REGION")
	return cloudvm.NewAWSNitroConfidentialAdapter(
		cloudvm.NewAWSProvider(region), eif, proxy, pcr0, os.Getenv("DISPATCHER_AWS_NITRO_INSTANCE_TYPE"),
		cloudvm.Config{ProviderID: cloudvm.ProviderAWS, Region: region, SSHUser: "ec2-user"},
	), nil
}

// newAzureSNPConfidentialAdapter builds the Azure measured-boot adapter (direct
// SNP+vTPM): a pinned custom measured image whose agent lives in a dm-verity root
// measured into PCR11. DISPATCHER_AZURE_SNP_IMAGE is the gallery image id and
// DISPATCHER_AZURE_SNP_PCR11 the pinned PCR11 (from deploy/azure-uki/mkosi). Fails
// closed when unconfigured.
func newAzureSNPConfidentialAdapter(_ context.Context) (adapter.TargetAdapter, error) {
	pin := confidential.Resolve(confidential.AzureSNP)
	image := orEnv(pin.Image, "DISPATCHER_AZURE_SNP_IMAGE")
	pcr11 := orEnv(pin.Measurement, "DISPATCHER_AZURE_SNP_PCR11")
	launchMeas := orEnv(pin.Extra["launchMeasurement"], "DISPATCHER_AZURE_SNP_LAUNCH_MEASUREMENT")
	if image == "" || pcr11 == "" || launchMeas == "" {
		return nil, fmt.Errorf("confidential Azure measured runs need the pinned measured image AND the SNP launch measurement: set DISPATCHER_AZURE_SNP_IMAGE " +
			"(a ConfidentialVm gallery image id), DISPATCHER_AZURE_SNP_PCR11 (its measured PCR11), and DISPATCHER_AZURE_SNP_LAUNCH_MEASUREMENT " +
			"(the SNP launch measurement that roots the vTPM AK — re-capture to record it); build with deploy/azure-uki/mkosi")
	}
	rg := os.Getenv("DISPATCHER_AZURE_RG")
	if rg == "" {
		rg = "dispatcher-rg"
	}
	location := os.Getenv("DISPATCHER_AZURE_LOCATION")
	return cloudvm.NewAzureSNPConfidentialAdapter(
		cloudvm.NewAzureProvider(rg, location), image, map[int]string{11: pcr11}, launchMeas,
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
	keys, err := attest.LoadGoogleCSKeys(ctx)
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
	// A pinned, digest-addressed image (the registry pin, or DISPATCHER_CS_AGENT_IMAGE)
	// skips the build — the digest IS the GCP measurement.
	if ref := orEnv(confidential.Resolve(confidential.GCP).Image, "DISPATCHER_CS_AGENT_IMAGE"); ref != "" {
		at := strings.Index(ref, "@sha256:")
		if at < 0 {
			return nil, fmt.Errorf("DISPATCHER_CS_AGENT_IMAGE must be digest-pinned (…@sha256:…), got %q", ref)
		}
		digest := ref[at+1:]
		if err := confidential.ValidateImageDigest(digest); err != nil {
			return nil, fmt.Errorf("DISPATCHER_CS_AGENT_IMAGE: %w", err)
		}
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
