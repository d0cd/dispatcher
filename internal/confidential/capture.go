package confidential

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Capturing a measurement is the middle of the pipeline (build -> capture -> pin).
// The build is cloud-specific and infra-heavy (docker / nitro-cli / mkosi); these
// functions parse each build's output into the pinnable measurement, so the
// capture step is deterministic and shared.

// CaptureGCP returns the pin for a digest-pinned Confidential Space image — the
// container digest IS the attested measurement.
func CaptureGCP(imageRef string) (Pin, error) {
	at := strings.Index(imageRef, "@sha256:")
	if at < 0 {
		return Pin{}, fmt.Errorf("image must be digest-pinned (…@sha256:…), got %q", imageRef)
	}
	return Pin{Image: imageRef, Measurement: imageRef[at+1:]}, nil
}

// CaptureNitroPCR0 extracts PCR0 (the enclave-image measurement) from the JSON
// `nitro-cli describe-eif` (or build-enclave) emits.
func CaptureNitroPCR0(describeEIF []byte) (string, error) {
	var d struct {
		Measurements struct {
			PCR0 string `json:"PCR0"`
		} `json:"Measurements"`
	}
	if err := json.Unmarshal(describeEIF, &d); err != nil {
		return "", fmt.Errorf("parse nitro-cli output: %w", err)
	}
	if d.Measurements.PCR0 == "" {
		return "", fmt.Errorf("no PCR0 in nitro-cli output")
	}
	return d.Measurements.PCR0, nil
}

// CaptureAzurePCR11 extracts PCR11 (hex) from the in-CVM agent's /attest evidence
// bundle (the base64-JSON "token"), the same evidence the verifier consumes. The
// measured CVM must be booted from the pinned image to read its real PCR11.
func CaptureAzurePCR11(attestToken string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(attestToken)
	if err != nil {
		return "", fmt.Errorf("decode evidence: %w", err)
	}
	var ev struct {
		PCRs map[string]string `json:"pcrs"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		return "", fmt.Errorf("parse evidence: %w", err)
	}
	b64, ok := ev.PCRs["11"]
	if !ok || b64 == "" {
		return "", fmt.Errorf("evidence carries no pcr11")
	}
	pcr, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode pcr11: %w", err)
	}
	return hex.EncodeToString(pcr), nil
}
