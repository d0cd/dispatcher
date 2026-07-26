package workload

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// OperatorConfig is the user-global dispatcher configuration
// (~/.config/dispatcher/config.yaml): operator-level settings that aren't
// per-workload, such as secret-resolution commands for provider credentials.
type OperatorConfig struct {
	// Secrets maps an environment-variable name to a command whose stdout supplies
	// its value, so a credential need never be written in plaintext. See
	// DispatcherConfig.Secrets; a per-project dispatcher.yaml entry overrides this.
	Secrets map[string][]string `yaml:"secrets,omitempty"`
}

// OperatorConfigPath returns the user-global config path, honoring
// $XDG_CONFIG_HOME and falling back to ~/.config/dispatcher/config.yaml.
func OperatorConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "dispatcher", "config.yaml")
}

// LoadOperatorConfig reads the user-global config. A missing file is not an error
// (returns an empty config); a malformed file fails closed so a typo can't
// silently drop a configured credential command.
func LoadOperatorConfig() (*OperatorConfig, error) {
	path := OperatorConfigPath()
	if path == "" {
		return &OperatorConfig{}, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &OperatorConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read operator config %s: %w", path, err)
	}
	var c OperatorConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse operator config %s: %w", path, err)
	}
	return &c, nil
}
