package cloudvm

import "fmt"

// validateLabelKV requires `[a-zA-Z0-9_.-]` on cloud tag/label keys and
// values — a strict subset of every provider's documented charset and
// every CLI argument separator/quote. Validating at the boundary avoids
// having to reason about which provider re-tokenizes which character.
func validateLabelKV(k, v string) error {
	if k == "" {
		return fmt.Errorf("label key is empty")
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
