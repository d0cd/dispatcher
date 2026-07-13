package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/plan"
	"github.com/d0cd/dispatcher/internal/types"
)

// The measured Azure SNP and AWS Nitro backends are selected by
// confidential.profile in dispatcher.yaml. This walks the real config surface
// (yaml → LoadConfig/ApplyConfig → plan.Build) and asserts the run dispatcher's
// selectors fire — the path the audit found unreachable because the profile
// discriminator did not exist end to end.
// The confidential block signals requirement by presence; confidentialBody is
// its indented fields.
func buildConfidentialPlan(t *testing.T, target, confidentialBody string) *types.Plan {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`print("hi")`), 0o644))
	yaml := "confidential:\n" + confidentialBody
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dispatcher.yaml"), []byte(yaml), 0o644))

	p, err := plan.Build(dir, types.PlanConstraints{TargetName: target}, nil)
	require.NoError(t, err)
	require.True(t, p.Workload.Requirements.Confidential.Required, "confidential block must load (invalid yaml is silently ignored)")
	return p
}

func TestDispatch_AzureSNPProfileIsReachable(t *testing.T) {
	p := buildConfidentialPlan(t, "azure-vm", "  profile: azure-snp\n")
	assert.True(t, usesAzureSNP(p), "confidential.profile: azure-snp must select the measured Azure SNP path")
	assert.False(t, usesAzureConfidential(p), "azure-snp must not also match the MAA path")
}

func TestDispatch_AWSNitroProfileIsReachable(t *testing.T) {
	p := buildConfidentialPlan(t, "aws-vm", "  profile: nitro\n")
	assert.True(t, usesAWSNitro(p), "confidential.profile: nitro must select the Nitro path")
	assert.False(t, usesAWSConfidential(p), "nitro must not also match the SEV-SNP path")
}

// The default (no profile) confidential run still takes the standard
// MAA/SEV-SNP backend for its target.
func TestDispatch_DefaultProfileTakesStandardBackend(t *testing.T) {
	p := buildConfidentialPlan(t, "azure-vm", "  attestation: required\n")
	assert.True(t, usesAzureConfidential(p), "no profile → standard Azure MAA path")
	assert.False(t, usesAzureSNP(p))
}

// A confidential plan must resolve to a confidential (attesting) adapter via
// adapterForPlan — never fall through to the plain target adapter. The plain
// adapter resolves with no error, which is exactly why routing a confidential
// shard through adapterForTarget silently stripped attestation.
func TestAdapterForPlan_ConfidentialRunFailsClosedNotPlain(t *testing.T) {
	t.Setenv("DISPATCHER_AWS_AGENT_BIN", "") // unconfigured → confidential adapter fails closed

	confPlan := &types.Plan{
		Recommendation: &types.Recommendation{Target: "aws-vm"},
		Workload: types.WorkloadSpec{Requirements: types.ResourceRequirements{
			Confidential: types.ConfidentialRequirement{Required: true, Attestation: "required"},
		}},
	}

	_, err := adapterForPlan(context.Background(), confPlan)
	require.Error(t, err, "a confidential plan must select the attesting adapter (fail-closed when unconfigured), not a plain VM adapter")

	// The plain path the shard code used to call returns a working adapter with
	// no error — the bypass.
	_, plainErr := adapterForTarget("aws-vm")
	require.NoError(t, plainErr)
}

// A measured profile on a mismatched provider target must fail closed in the
// dispatch, not silently route to that provider's unmeasured default backend.
func TestAdapterForPlan_ProfileTargetMismatchFailsClosed(t *testing.T) {
	p := &types.Plan{
		Recommendation: &types.Recommendation{Target: "azure-vm"},
		Workload: types.WorkloadSpec{Requirements: types.ResourceRequirements{
			Confidential: types.ConfidentialRequirement{Required: true, Attestation: "required", Profile: "nitro"},
		}},
	}
	_, err := adapterForPlan(context.Background(), p)
	require.Error(t, err, "profile nitro on azure-vm must fail closed, not route to the Azure MAA adapter")
	assert.Contains(t, err.Error(), "nitro")
}

// A DISPATCHER_MAA_URL carrying shell metacharacters must be rejected at the
// boundary — it is interpolated into a guest-side `sudo bash -c '...'`.
func TestNewAzureConfidentialAdapter_RejectsUnsafeMAAURL(t *testing.T) {
	t.Setenv("DISPATCHER_MAA_URL", "https://evil'; touch /pwned #")
	t.Setenv("DISPATCHER_AZURE_AGENT_BIN", "/tmp/agent")

	_, err := newAzureConfidentialAdapter(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DISPATCHER_MAA_URL")
}
