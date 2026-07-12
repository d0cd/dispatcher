package confidential

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCaptureGCP: the GCP measurement is the (shape-validated) image digest of a
// digest-pinned ref.
func TestCaptureGCP(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32) // 64 hex
	pin, err := CaptureGCP("us-docker.pkg.dev/p/r/agent@" + digest)
	require.NoError(t, err)
	assert.Equal(t, digest, pin.Measurement)
	assert.Equal(t, "us-docker.pkg.dev/p/r/agent@"+digest, pin.Image)

	_, err = CaptureGCP("us-docker.pkg.dev/p/r/agent:latest")
	require.Error(t, err, "a non-digest-pinned ref has no fixed measurement")
}

// TestCaptureGCP_RejectsMalformedDigest: an empty, short, non-hex, or duplicated
// digest is the measurement, so it must be rejected rather than pinned.
func TestCaptureGCP_RejectsMalformedDigest(t *testing.T) {
	for _, ref := range []string{
		"r@sha256:",                            // empty
		"r@sha256:beef",                        // too short
		"r@sha256:" + strings.Repeat("zz", 32), // non-hex
		"r@sha256:" + strings.Repeat("ab", 32) + "@sha256:" + strings.Repeat("cd", 32), // duplicated
	} {
		_, err := CaptureGCP(ref)
		require.Error(t, err, "malformed digest %q must be rejected", ref)
	}
}

// TestCaptureNitroPCR0: PCR0 (SHA-384, 96 hex) is parsed and validated from
// `nitro-cli describe-eif` JSON.
func TestCaptureNitroPCR0(t *testing.T) {
	pcr0hex := strings.Repeat("84", 48) // 96 hex
	out := []byte(`{"Measurements":{"HashAlgorithm":"Sha384 { ... }","PCR0":"` + pcr0hex + `","PCR1":"4b4d5b"}}`)
	pcr0, err := CaptureNitroPCR0(out)
	require.NoError(t, err)
	assert.Equal(t, pcr0hex, pcr0)

	_, err = CaptureNitroPCR0([]byte(`{"Measurements":{}}`))
	require.Error(t, err, "missing PCR0 must fail")

	_, err = CaptureNitroPCR0([]byte(`{"Measurements":{"PCR0":"8410c2ae4dce"}}`))
	require.Error(t, err, "a short/malformed PCR0 must fail")
}
