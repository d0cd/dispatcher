package workload

import (
	"os"
	"path/filepath"

	"github.com/d0cd/dispatcher/internal/types"
	"gopkg.in/yaml.v3"
)

// DispatchConfig is the user-facing dispatch.yaml structure.
type DispatchConfig struct {
	Name    string             `yaml:"name"`
	Image   string             `yaml:"image,omitempty"`
	Command []string           `yaml:"command,omitempty"`
	GPU     *DispatchGPUConfig `yaml:"gpu,omitempty"`
	Service *DispatchService   `yaml:"service,omitempty"`
	Sandbox bool               `yaml:"sandbox,omitempty"`
	MaxCost float64            `yaml:"maxCost,omitempty"`
	MaxTime string             `yaml:"maxTime,omitempty"`
	Target  string             `yaml:"target,omitempty"`
}

// DispatchGPUConfig describes GPU requirements in dispatch.yaml.
type DispatchGPUConfig struct {
	Count     int    `yaml:"count"`
	Model     string `yaml:"model,omitempty"`
	Framework string `yaml:"framework,omitempty"`
}

// DispatchService describes service configuration in dispatch.yaml.
type DispatchService struct {
	Port int `yaml:"port"`
}

// LoadConfig reads dispatch.yaml from the given directory.
// Returns nil if no config file is found (not an error).
func LoadConfig(dir string) (*DispatchConfig, error) {
	for _, name := range []string{"dispatch.yaml", "dispatch.yml"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg DispatchConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
		return &cfg, nil
	}
	return nil, nil
}

// ApplyConfig merges a DispatchConfig into a WorkloadSpec.
// Config values take precedence over auto-detected values.
func ApplyConfig(spec *types.WorkloadSpec, cfg *DispatchConfig) {
	if cfg == nil {
		return
	}

	if cfg.Name != "" {
		spec.Name = cfg.Name
	}

	if len(cfg.Command) > 0 {
		spec.Command = cfg.Command
	}

	if cfg.Image != "" {
		spec.Package = types.PackagePlan{
			Type:          types.PackageTypeImage,
			BuildRequired: false,
		}
	}

	if cfg.GPU != nil {
		spec.Requirements.GPU = types.GPURequirement{
			Required:  true,
			Count:     cfg.GPU.Count,
			Model:     cfg.GPU.Model,
			Framework: cfg.GPU.Framework,
		}
		if spec.Requirements.GPU.Count == 0 {
			spec.Requirements.GPU.Count = 1
		}
		spec.DetectedKind = types.WorkloadKindGPUJob
	}

	if cfg.Service != nil && cfg.Service.Port > 0 {
		// Add port if not already detected
		found := false
		for _, p := range spec.Ports {
			if p == cfg.Service.Port {
				found = true
				break
			}
		}
		if !found {
			spec.Ports = append(spec.Ports, cfg.Service.Port)
		}
		spec.DetectedKind = types.WorkloadKindService
	}

	if cfg.Sandbox {
		spec.DetectedKind = types.WorkloadKindSandbox
	}
}
