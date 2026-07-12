package confidential

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCaptureGCP: the GCP measurement is the image digest of a digest-pinned ref.
func TestCaptureGCP(t *testing.T) {
	pin, err := CaptureGCP("us-docker.pkg.dev/p/r/agent@sha256:cafebabe")
	require.NoError(t, err)
	assert.Equal(t, "sha256:cafebabe", pin.Measurement)
	assert.Equal(t, "us-docker.pkg.dev/p/r/agent@sha256:cafebabe", pin.Image)

	_, err = CaptureGCP("us-docker.pkg.dev/p/r/agent:latest")
	require.Error(t, err, "a non-digest-pinned ref has no fixed measurement")
}

// TestCaptureNitroPCR0: PCR0 is parsed from `nitro-cli describe-eif` JSON.
func TestCaptureNitroPCR0(t *testing.T) {
	out := []byte(`{"Measurements":{"HashAlgorithm":"Sha384 { ... }","PCR0":"8410c2ae4dce","PCR1":"4b4d5b","PCR2":"d420fd"}}`)
	pcr0, err := CaptureNitroPCR0(out)
	require.NoError(t, err)
	assert.Equal(t, "8410c2ae4dce", pcr0)

	_, err = CaptureNitroPCR0([]byte(`{"Measurements":{}}`))
	require.Error(t, err, "missing PCR0 must fail")
}

// TestCaptureAzurePCR11: PCR11 is parsed (hex) from the agent's /attest evidence
// bundle (base64 JSON), the same evidence the verifier consumes.
func TestCaptureAzurePCR11(t *testing.T) {
	pcr11 := make([]byte, 32)
	for i := range pcr11 {
		pcr11[i] = 0x81
	}
	bundle, err := json.Marshal(map[string]any{
		"pcrs": map[string]string{"11": base64.StdEncoding.EncodeToString(pcr11)},
	})
	require.NoError(t, err)
	token := base64.StdEncoding.EncodeToString(bundle)

	got, err := CaptureAzurePCR11(token)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(pcr11), got)

	_, err = CaptureAzurePCR11(base64.StdEncoding.EncodeToString([]byte(`{"pcrs":{}}`)))
	require.Error(t, err, "missing PCR11 must fail")
}
