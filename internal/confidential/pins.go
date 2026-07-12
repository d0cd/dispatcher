// Package confidential is the cross-cloud lifecycle for measured confidential
// images: build the measured artifact, capture its measurement, pin it, and let
// the run path read the pin. The three clouds differ only in the artifact and the
// measurement's shape — GCP's container digest, AWS Nitro's PCR0, Azure's PCR11 —
// so the pin registry and command surface are shared. Measurements are
// content-addressed and change on every rebuild, so build+capture re-writes the pin.
package confidential

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	statedir "github.com/d0cd/dispatcher/internal/state"
)

// Target identifies a confidential execution target whose agent is measured.
type Target string

const (
	GCP      Target = "gcp"       // Confidential Space container (digest = measurement)
	AWSNitro Target = "aws-nitro" // Nitro Enclave (PCR0)
	AzureSNP Target = "azure-snp" // measured CVM, direct SNP+vTPM (PCR11)
)

// Pin is the current measured image + its measurement for a target. Extra holds
// target-specific artifacts (e.g. the Nitro parent proxy binary path).
type Pin struct {
	Image       string            `yaml:"image"`                 // container ref / EIF path / gallery image id
	Measurement string            `yaml:"measurement"`           // digest / PCR0 / PCR11
	Extra       map[string]string `yaml:"extra,omitempty"`       // target-specific artifacts
	CapturedAt  string            `yaml:"captured_at,omitempty"` // when the measurement was captured
}

// Registry is the single source of truth for measured-image pins: the run path
// reads it, the build+capture flow writes it. Persisted as YAML.
type Registry struct {
	Pins map[Target]Pin `yaml:"pins"`
}

// Load reads the registry from path. A missing file is an empty registry (not an
// error) so a fresh checkout works and callers fall back to env vars.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Registry{Pins: map[Target]Pin{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read confidential pins %s: %w", path, err)
	}
	var r Registry
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse confidential pins %s: %w", path, err)
	}
	if r.Pins == nil {
		r.Pins = map[Target]Pin{}
	}
	return &r, nil
}

// Save writes the registry to path atomically (0600 — it records image identities,
// not secrets, but stays with the run state's posture).
func (r *Registry) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create pins dir: %w", err)
	}
	data, err := yaml.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal pins: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write pins: %w", err)
	}
	return os.Rename(tmp, path)
}

// Get returns the pin for a target, or false if unset.
func (r *Registry) Get(t Target) (Pin, bool) {
	if r.Pins == nil {
		return Pin{}, false
	}
	p, ok := r.Pins[t]
	return p, ok
}

// Set records (or replaces) the pin for a target.
func (r *Registry) Set(t Target, p Pin) {
	if r.Pins == nil {
		r.Pins = map[Target]Pin{}
	}
	r.Pins[t] = p
}

// Resolve returns the pin for a target from the default registry, or an empty pin
// (never an error) when there's no registry or no pin — callers then fall back to
// environment variables. This is how the run path reads the registry without every
// caller handling load errors.
func Resolve(t Target) Pin {
	path, err := DefaultPath()
	if err != nil {
		return Pin{}
	}
	r, err := Load(path)
	if err != nil {
		return Pin{}
	}
	p, _ := r.Get(t)
	return p
}

// DefaultPath is where the registry lives by default: the dispatcher state dir.
func DefaultPath() (string, error) {
	dir, err := statedir.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "confidential-pins.yaml"), nil
}
