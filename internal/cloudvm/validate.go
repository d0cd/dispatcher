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
