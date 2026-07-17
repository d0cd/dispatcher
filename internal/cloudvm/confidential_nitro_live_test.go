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

// TestGolden_NitroLiveAdapter exercises the FULLY INTEGRATED AWSNitroConfidential
// Adapter against real AWS: provision an enclave-enabled parent, install nitro-cli,
// ship the pinned EIF + proxy, run the enclave, attest (Nitro doc → Root-G1 + PCR0),
// seal source/.env, run inside the enclave, retrieve the sealed result, and tear
// down. Gated on DISPATCHER_NITRO_LIVE_BUILD. The EIF + PCR0 must be pre-built
// (deploy/nitro/build-eif.sh on a Nitro instance).
//
//	DISPATCHER_NITRO_LIVE_BUILD=1 \
//	DISPATCHER_AWS_NITRO_EIF=<path> DISPATCHER_AWS_NITRO_PCR0=<hex> \
//	DISPATCHER_AWS_NITRO_PROXY_BIN=<linux/amd64 dispatcher-nitro-proxy> \
//	DISPATCHER_AWS_REGION=us-east-1 \
//	go test ./internal/cloudvm -run TestGolden_NitroLiveAdapter -v -timeout 20m
func TestGolden_NitroLiveAdapter(t *testing.T) {
	if os.Getenv("DISPATCHER_NITRO_LIVE_BUILD") == "" {
		t.Skip("set DISPATCHER_NITRO_LIVE_BUILD=1 (+ EIF/PCR0/proxy/region) to run the integrated live path")
	}
	eif := os.Getenv("DISPATCHER_AWS_NITRO_EIF")
	pcr0 := strings.TrimSpace(os.Getenv("DISPATCHER_AWS_NITRO_PCR0"))
	proxy := os.Getenv("DISPATCHER_AWS_NITRO_PROXY_BIN")
	region := os.Getenv("DISPATCHER_AWS_REGION")
	require.NotEmpty(t, eif)
	require.NotEmpty(t, pcr0)
	require.NotEmpty(t, proxy)

	ctx := context.Background()
	a := NewAWSNitroConfidentialAdapter(NewAWSProvider(region), eif, proxy, pcr0, "",
		Config{ProviderID: ProviderAWS, Region: region, SSHUser: "ec2-user"})

	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, ".env"), []byte("SECRET=nitro-adapter\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "hello.txt"), []byte("from-source\n"), 0o644))
	p := &types.Plan{
		Metadata: types.PlanMetadata{ID: "nitrolive"},
		Workload: types.WorkloadSpec{
			Name: "nitrolive", Source: types.WorkloadSource{Path: src},
			Command:      []string{"sh", "-c", "echo adapter=$SECRET; cat hello.txt"},
			Requirements: types.ResourceRequirements{Confidential: types.ConfidentialRequirement{Required: true, Type: "nitro"}},
		},
	}

	h, err := a.Execute(ctx, p)
	require.NoError(t, err, "integrated Nitro confidential run must succeed")
	t.Cleanup(func() { _, _ = a.Cleanup(context.Background(), h) })

	st := h.State.(*confidentialRunState)
	assert.True(t, st.Attestation.Verified)
	assert.Equal(t, pcr0, st.Attestation.Measurement, "the attested measurement is the pinned enclave PCR0")
	assert.Equal(t, 0, st.Result.ExitCode)
	assert.Contains(t, string(st.Result.Stdout), "adapter=nitro-adapter", "the sealed .env reached the enclave")
	assert.Contains(t, string(st.Result.Stdout), "from-source", "the sealed source reached the enclave")

	status, err := a.Status(ctx, h)
	require.NoError(t, err)
	assert.Equal(t, types.RunStateCompleted, status)
}
