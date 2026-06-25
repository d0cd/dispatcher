package target

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
	"gopkg.in/yaml.v3"
)

// TargetsFile is the YAML structure for a file containing target definitions.
type TargetsFile struct {
	Targets []types.TargetConfig `yaml:"targets"`
}

// LoadFromFile loads target definitions from a YAML file into the registry.
// Targets loaded from files override builtins with the same ID.
func (r *Registry) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read targets file %s: %w", path, err)
	}

	var tf TargetsFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return fmt.Errorf("cannot parse targets file %s: %w", path, err)
	}

	for _, t := range tf.Targets {
		if t.ID == "" {
			return fmt.Errorf("target in %s is missing required field 'id'", path)
		}
		r.Add(t)
	}

	return nil
}

// LoadFromDir loads all .yaml/.yml files from a directory into the registry.
func (r *Registry) LoadFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // directory doesn't exist, not an error
		}
		return fmt.Errorf("cannot read targets directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		if err := r.LoadFromFile(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}

	return nil
}

// LoadUserConfig loads targets from the standard user config locations:
//  1. <state-dir>/targets/*.yaml (per-project when ./.dispatcher/ exists, else ~/.dispatcher/)
//  2. ./dispatcher.yaml (project-local targets, "targets:" key)
func (r *Registry) LoadUserConfig() error {
	if targetsDir, err := state.Subdir("targets"); err == nil {
		if err := r.LoadFromDir(targetsDir); err != nil {
			return fmt.Errorf("loading user targets: %w", err)
		}
	}

	if err := r.LoadProjectConfig("."); err != nil {
		return err
	}

	return nil
}

// validateTargetID rejects empty ids and ids that could escape the targets
// directory. Shared by SaveTarget, DeleteTarget, and the importer.
func validateTargetID(id string) error {
	if id == "" {
		return fmt.Errorf("target id is empty")
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid target id %q: contains path separator or traversal", id)
	}
	return nil
}

// ValidateSSHTarget checks an SSH target's connection fields at the trust
// boundary. host and user are interpolated into ssh/rsync argv as `user@host`,
// so they must not carry shell or ssh-option metacharacters; key_file is a path.
// Shared by SaveTarget, `targets add`, and the bring-your-own-hosts importer so
// no path can persist a target that would inject into ssh.
func ValidateSSHTarget(c *types.SSHTargetConfig) error {
	if c == nil {
		return fmt.Errorf("ssh config is nil")
	}
	if err := validateSSHHost(c.Host); err != nil {
		return err
	}
	if c.User != "" {
		if err := validateSSHWord("user", c.User); err != nil {
			return err
		}
	}
	if c.KeyFile != "" {
		if err := validateSSHKeyFile(c.KeyFile); err != nil {
			return err
		}
	}
	return nil
}

func validateSSHHost(host string) error {
	if host == "" {
		return fmt.Errorf("ssh host is empty")
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf("ssh host %q is flag-like (leading '-')", host)
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return fmt.Errorf("ssh host %q contains characters outside [a-zA-Z0-9.-] (no ':' '/' '@'; IPv6 literals unsupported)", host)
		}
	}
	return nil
}

func validateSSHWord(field, val string) error {
	if strings.HasPrefix(val, "-") {
		return fmt.Errorf("ssh %s %q is flag-like (leading '-')", field, val)
	}
	for _, r := range val {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return fmt.Errorf("ssh %s %q contains characters outside [a-zA-Z0-9_.-]", field, val)
		}
	}
	return nil
}

func validateSSHKeyFile(path string) error {
	if strings.HasPrefix(path, "-") {
		return fmt.Errorf("ssh key_file %q is flag-like (leading '-')", path)
	}
	if strings.ContainsAny(path, "\x00\n\r") {
		return fmt.Errorf("ssh key_file %q contains a NUL or newline", path)
	}
	return nil
}

// DeleteTarget removes the user-defined target file at
// <state-dir>/targets/<id>.yaml (the file SaveTarget writes). Builtins and
// project-local `dispatcher.yaml` targets have no such file and aren't
// removable here. Applies the same id validation as SaveTarget so a crafted
// id can't escape the targets directory.
func DeleteTarget(id string) (string, error) {
	if err := validateTargetID(id); err != nil {
		return "", err
	}
	dir, err := state.Subdir("targets")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, id+".yaml")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("no user-defined target %q to remove (builtins and dispatcher.yaml targets are not removable)", id)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("cannot remove target file: %w", err)
	}
	return path, nil
}

// LoadProjectConfig loads targets from dispatcher.yaml in the given directory.
func (r *Registry) LoadProjectConfig(dir string) error {
	for _, name := range []string{"dispatcher.yaml", "dispatcher.yml"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		return r.LoadFromFile(path)
	}
	return nil // no project config found, not an error
}

// SaveTarget writes a single target definition to <state-dir>/targets/<id>.yaml.
// Defense in depth: rejects IDs with path separators / traversal so a
// `dispatcher targets add --id "../etc/passwd"` invocation can't escape the
// targets directory.
func SaveTarget(t types.TargetConfig) (string, error) {
	if err := validateTargetID(t.ID); err != nil {
		return "", err
	}
	if t.SSH != nil {
		if err := ValidateSSHTarget(t.SSH); err != nil {
			return "", fmt.Errorf("invalid ssh target %q: %w", t.ID, err)
		}
	}
	dir, err := state.Subdir("targets")
	if err != nil {
		return "", err
	}

	tf := TargetsFile{Targets: []types.TargetConfig{t}}
	data, err := yaml.Marshal(tf)
	if err != nil {
		return "", fmt.Errorf("cannot marshal target: %w", err)
	}

	path := filepath.Join(dir, t.ID+".yaml")
	// 0o600: target configs reference SSH key paths and host details that
	// shouldn't be readable by other users on the host.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("cannot write target file: %w", err)
	}

	return path, nil
}
