package cli

import (
	"testing"

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
