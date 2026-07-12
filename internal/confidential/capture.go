package confidential

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Capturing a measurement is the middle of the pipeline (build -> capture -> pin).
// The build is cloud-specific and infra-heavy (docker / nitro-cli / mkosi); these
// functions parse each build's output into the pinnable measurement, so the
// capture step is deterministic and shared.

// CaptureGCP returns the pin for a digest-pinned Confidential Space image — the
// container digest IS the attested measurement, so it is validated for shape.
func CaptureGCP(imageRef string) (Pin, error) {
	at := strings.Index(imageRef, "@sha256:")
	if at < 0 {
		return Pin{}, fmt.Errorf("image must be digest-pinned (…@sha256:…), got %q", imageRef)
	}
	digest := imageRef[at+1:]
	if err := ValidateImageDigest(digest); err != nil {
		return Pin{}, err
	}
	return Pin{Image: imageRef, Measurement: digest}, nil
}

// ValidateImageDigest checks a container image digest is sha256:<64 lowercase hex>
// — the canonical shape GCP Confidential Space attests. The digest IS the pinned
// measurement, so a truncated/typo'd/duplicated (…@sha256:…@sha256:…) value must be
// rejected, not silently pinned.
func ValidateImageDigest(digest string) error {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || !isHexLen(hexPart, 64) {
		return fmt.Errorf("image digest must be sha256:<64 hex>, got %q", digest)
	}
	return nil
}

// CaptureNitroPCR0 extracts PCR0 (the enclave-image measurement) from the JSON
// `nitro-cli describe-eif` (or build-enclave) emits. PCR0 is a SHA-384 (96 hex)
// value; it is validated so a malformed measurement is never pinned.
func CaptureNitroPCR0(describeEIF []byte) (string, error) {
	var d struct {
		Measurements struct {
			PCR0 string `json:"PCR0"`
		} `json:"Measurements"`
	}
	if err := json.Unmarshal(describeEIF, &d); err != nil {
		return "", fmt.Errorf("parse nitro-cli output: %w", err)
	}
	if !isHexLen(d.Measurements.PCR0, 96) {
		return "", fmt.Errorf("nitro-cli PCR0 must be 96 hex chars (SHA-384), got %q", d.Measurements.PCR0)
	}
	return d.Measurements.PCR0, nil
}

// isHexLen reports whether s is exactly n lowercase hex digits.
func isHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
