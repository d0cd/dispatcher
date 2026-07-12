package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/confidential"
)

func TestParseTarget(t *testing.T) {
	for _, s := range []string{"gcp", "aws-nitro", "azure-snp"} {
		got, err := parseTarget(s)
		require.NoError(t, err)
		assert.Equal(t, confidential.Target(s), got)
	}
	_, err := parseTarget("sev-snp")
	require.Error(t, err, "an unknown target is rejected")
	assert.Contains(t, err.Error(), "gcp | aws-nitro | azure-snp")
}

func TestCaptureMeasurement_GCP(t *testing.T) {
	pin, err := captureMeasurement(confidential.GCP, "us-docker.pkg.dev/p/r@sha256:beef")
	require.NoError(t, err)
	assert.Equal(t, "sha256:beef", pin.Measurement)

	_, err = captureMeasurement(confidential.GCP, "us-docker.pkg.dev/p/r:latest")
	require.Error(t, err, "a non-digest-pinned GCP image has no measurement")
}

func TestBuildNitro_RequiresProxy(t *testing.T) {
	confidentialBuildFlags.proxy = ""
	err := buildNitro(&cobra.Command{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--proxy is required")
}

// TestConfidentialBuild_GuidanceForNonNitro: gcp/azure have no single-host build,
// so `build` returns actionable guidance instead of pretending.
func TestConfidentialBuild_GuidanceForNonNitro(t *testing.T) {
	for _, tc := range []struct{ target, want string }{
		{"gcp", "per-run workload container"},
		{"azure-snp", "multi-host build"},
	} {
		err := confidentialBuildCmd.RunE(&cobra.Command{}, []string{tc.target})
		require.Error(t, err)
		assert.Contains(t, err.Error(), tc.want)
	}
}
