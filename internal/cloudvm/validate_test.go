package cloudvm

import "testing"

func TestValidateLabelKV(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		value   string
		wantErr bool
	}{
		{"basic", "dispatcher", "true", false},
		{"with-runid", "dispatcher-run-id", "run_abc123", false},
		{"hyphen-dot-underscore", "k.e_y", "v-a_l.ue", false},
		{"empty-key", "", "v", true},
		{"empty-value-ok", "k", "", false},
		{"space-in-key", "my key", "v", true},
		{"space-in-value", "k", "my value", true},
		{"comma-injection", "k", "v,extra=injected", true},
		{"equals-injection", "k", "v=injected", true},
		{"newline", "k", "v\nmore", true},
		{"shell-meta", "k", "v$(echo bad)", true},
		{"quotes", "k", `v"injected`, true},
		{"leading-dash-key-is-flag-injection", "--admin-password", "v", true},
		{"leading-dash-value-is-flag-injection", "k", "-rf", true},
		{"unicode-rejected", "k", "café", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateLabelKV(c.key, c.value)
			if (err != nil) != c.wantErr {
				t.Fatalf("wantErr=%v got err=%v", c.wantErr, err)
			}
		})
	}
}
