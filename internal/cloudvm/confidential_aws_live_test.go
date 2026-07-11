package cloudvm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

// TestGolden_AWSLiveAdapter exercises the FULLY INTEGRATED AWSConfidentialAdapter
// against real AWS: provision a SEV-SNP instance, scp+start the agent, open the
// security group, verify a raw SEV-SNP report (go-sev-guest + VLEK chain), seal
// source/.env, run inside the TEE, retrieve the sealed result, and tear down.
// Gated on DISPATCHER_AWS_LIVE_BUILD.
func TestGolden_AWSLiveAdapter(t *testing.T) {
	if os.Getenv("DISPATCHER_AWS_LIVE_BUILD") == "" {
		t.Skip("set DISPATCHER_AWS_LIVE_BUILD=1 (+ agent bin/region/measurement) to run the integrated live path")
	}
	agentBin := os.Getenv("DISPATCHER_AWS_AGENT_BIN")
	region := os.Getenv("DISPATCHER_AWS_REGION")
	measurement := strings.TrimSpace(os.Getenv("DISPATCHER_AWS_LIVE_MEASUREMENT"))
	require.NotEmpty(t, agentBin)
	require.NotEmpty(t, measurement)

	a := NewAWSConfidentialAdapter(NewAWSProvider(region), agentBin,
		Config{ProviderID: ProviderAWS, Region: region, SSHUser: "ubuntu"})

	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, ".env"), []byte("SECRET=integrated\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "hello.txt"), []byte("from-source\n"), 0o644))
	p := &types.Plan{
		Metadata: types.PlanMetadata{ID: "awslive"},
		Workload: types.WorkloadSpec{
			Name: "awslive", Source: types.WorkloadSource{Path: src},
			Command:      []string{"sh", "-c", "echo integrated=$SECRET; cat hello.txt"},
			Requirements: types.ResourceRequirements{Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{measurement}}},
		},
	}

	h, err := a.Execute(context.Background(), p)
	require.NoError(t, err, "integrated AWS confidential run must succeed")
	t.Cleanup(func() { _, _ = a.Cleanup(context.Background(), h) })

	st := h.State.(*confidentialRunState)
	assert.True(t, st.Attestation.Verified)
	assert.Equal(t, 0, st.Result.ExitCode)
	assert.Contains(t, string(st.Result.Stdout), "integrated=integrated", "the sealed .env reached the TEE")
	assert.Contains(t, string(st.Result.Stdout), "from-source", "the sealed source reached the TEE")

	status, err := a.Status(context.Background(), h)
	require.NoError(t, err)
	assert.Equal(t, types.RunStateCompleted, status)
}
