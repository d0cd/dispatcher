package target

import (
	"fmt"
	"os"
	"path/filepath"

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
//  2. ./dispatch.yaml (project-local targets, "targets:" key)
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

// LoadProjectConfig loads targets from dispatch.yaml in the given directory.
func (r *Registry) LoadProjectConfig(dir string) error {
	for _, name := range []string{"dispatch.yaml", "dispatch.yml"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		return r.LoadFromFile(path)
	}
	return nil // no project config found, not an error
}

// SaveTarget writes a single target definition to <state-dir>/targets/<id>.yaml.
func SaveTarget(t types.TargetConfig) (string, error) {
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
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("cannot write target file: %w", err)
	}

	return path, nil
}
