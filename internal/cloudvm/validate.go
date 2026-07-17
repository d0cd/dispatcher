package cloudvm

import (
	"fmt"
	"net/url"
)

// ValidateAgentURL guards a confidential-agent endpoint URL (e.g. the MAA URL)
// before it is embedded in a remote `bash -c '...'` command. It requires an
// http(s) URL whose characters stay within isSafeArg's charset, so the value
// can never break out of the shell literal it is interpolated into.
func ValidateAgentURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid agent URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("agent URL %q must be http or https", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("agent URL %q has no host", raw)
	}
	if !isSafeArg(raw) {
		return fmt.Errorf("agent URL %q contains characters outside [a-zA-Z0-9_.:/@-]", raw)
	}
	return nil
}

// validateLabelKV requires `[a-zA-Z0-9_.-]` on cloud tag/label keys and
// values — a strict subset of every provider's documented charset and
// every CLI argument separator/quote. Validating at the boundary avoids
// having to reason about which provider re-tokenizes which character.
func validateLabelKV(k, v string) error {
	if k == "" {
		return fmt.Errorf("label key is empty")
	}
	// Reject a leading '-' on either side: Azure appends each tag as a bare `k=v`
	// token after `--tags`, so a key like "--admin-password" would reach `az` as a
	// real flag rather than a tag (flag injection). isSafeArg rejects it the same
	// way for argv tokens.
	if k[0] == '-' || (v != "" && v[0] == '-') {
		return fmt.Errorf("label %q=%q must not begin with '-' (would be read as a CLI flag)", k, v)
	}
	if !isSafeLabel(k) {
		return fmt.Errorf("label key %q contains characters outside [a-zA-Z0-9_.-]", k)
	}
	if !isSafeLabel(v) {
		return fmt.Errorf("label value %q contains characters outside [a-zA-Z0-9_.-]", v)
	}
	return nil
}

func isSafeLabel(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

func validateLabels(m map[string]string) error {
	for k, v := range m {
		if err := validateLabelKV(k, v); err != nil {
			return err
		}
	}
	return nil
}

// isSafeArg accepts a conservative charset for region/zone/instance-type/image
// values that are passed to cloud CLIs as standalone argv tokens. It is wider
// than isSafeLabel because image refs carry ':', '/', and '@' (e.g. Azure's
// "Canonical:ubuntu-24_04-lts:server:latest" or "ghcr.io/org/img@sha256:..."),
// but it still rejects empty values and a leading '-' so a value can never be
// reinterpreted as a flag, plus any whitespace/comma/quote that could corrupt
// a structured argument.
func isSafeArg(s string) bool {
	if s == "" || s[0] == '-' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-' || r == ':' || r == '/' || r == '@':
		default:
			return false
		}
	}
	return true
}

// destroyArgsSafe guards a resource's cloud-derived id and region before they
// are interpolated into a delete argv — defense-in-depth so a value can never
// be reinterpreted as a flag. Region may be empty (global/RG-scoped kinds).
func destroyArgsSafe(id, region string) bool {
	if !isSafeArg(id) {
		return false
	}
	if region != "" && !isSafeArg(region) {
		return false
	}
	return true
}

// validateVMArgs validates the resolved region, instance type, and image
// before they are interpolated into a provider's CLI argv.
func validateVMArgs(region, instanceType, image string) error {
	for _, f := range []struct{ name, val string }{
		{"region", region},
		{"instance type", instanceType},
		{"image", image},
	} {
		if !isSafeArg(f.val) {
			return fmt.Errorf("%s %q contains characters outside [a-zA-Z0-9_.:/@-] or is empty/flag-like", f.name, f.val)
		}
	}
	return nil
}
