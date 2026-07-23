package cloudvm

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforceWorkloadMeasurements(t *testing.T) {
	req := func(ms ...string) types.ConfidentialRequirement {
		return types.ConfidentialRequirement{Required: true, Measurements: ms}
	}

	// Empty allowlist → operator pins authoritative, no extra constraint.
	assert.NoError(t, enforceWorkloadMeasurements(req(), "abc123"))

	// Attested measurement in the allowlist → ok (case-insensitive, sha256: ignored).
	assert.NoError(t, enforceWorkloadMeasurements(req("ABC123"), "abc123"))
	assert.NoError(t, enforceWorkloadMeasurements(req("deadbeef"), "sha256:DEADBEEF"))
	assert.NoError(t, enforceWorkloadMeasurements(req("sha256:deadbeef"), "deadbeef"))

	// Attested measurement NOT in the allowlist → fail closed.
	err := enforceWorkloadMeasurements(req("aaaa", "bbbb"), "cccc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to run")
}
