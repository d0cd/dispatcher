package workload

import (
	"os"
	"path/filepath"

	"github.com/d0cd/dispatcher/internal/types"
)

// InspectCodebase scans a directory and returns a WorkloadSpec describing the detected workload.
func InspectCodebase(path string) (types.WorkloadSpec, error) {
	spec := types.WorkloadSpec{
		Name: filepath.Base(path),
		Source: types.WorkloadSource{
			Type: "repo",
			Path: path,
		},
		DetectedKind: types.WorkloadKindUnknown,
		Runtime:      types.RuntimeUnknown,
	}

	spec.Runtime = DetectRuntime(path)
	spec.Entrypoints = DetectEntrypoints(path)
	spec.Ports = DetectPorts(path)
	spec.Requirements.GPU = DetectGPURequirements(path)
	spec.Secrets = DetectSecrets(path)
	spec.Data = DetectDataRequirements(path)
	spec.Package = detectPackagePlan(path, spec.Runtime)
	spec.DetectedKind = classifyWorkload(spec)

	// Apply dispatch.yaml overrides if present
	if cfg, err := LoadConfig(path); err == nil && cfg != nil {
		ApplyConfig(&spec, cfg)
	}

	return spec, nil
}

func detectPackagePlan(path string, rt types.Runtime) types.PackagePlan {
	// Check for existing Dockerfile
	for _, name := range []string{"Dockerfile", "Dockerfile.dispatcher"} {
		if fileExists(filepath.Join(path, name)) {
			return types.PackagePlan{
				Type:          types.PackageTypeContainer,
				Dockerfile:    name,
				BuildRequired: true,
			}
		}
	}

	// Check for docker-compose
	for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		if fileExists(filepath.Join(path, name)) {
			return types.PackagePlan{
				Type:          types.PackageTypeContainer,
				BuildRequired: true,
			}
		}
	}

	// Generate package plan based on runtime
	base := baseImageForRuntime(rt)
	if base != "" {
		return types.PackagePlan{
			Type:          types.PackageTypeContainer,
			BuildRequired: true,
			BaseImage:     base,
		}
	}

	return types.PackagePlan{
		Type:          types.PackageTypeScript,
		BuildRequired: false,
	}
}

func baseImageForRuntime(rt types.Runtime) string {
	switch rt {
	case types.RuntimePython:
		return "python:3.11-slim"
	case types.RuntimeNode:
		return "node:20-slim"
	case types.RuntimeGo:
		return "golang:1.23"
	case types.RuntimeRust:
		return "rust:1.77"
	case types.RuntimeJava:
		return "eclipse-temurin:21"
	case types.RuntimeRuby:
		return "ruby:3.3-slim"
	default:
		return ""
	}
}

func classifyWorkload(spec types.WorkloadSpec) types.WorkloadKind {
	if spec.Requirements.GPU.Required {
		return types.WorkloadKindGPUJob
	}
	if len(spec.Ports) > 0 {
		return types.WorkloadKindService
	}
	if spec.Package.Dockerfile != "" {
		return types.WorkloadKindContainer
	}
	if spec.Runtime != types.RuntimeUnknown {
		return types.WorkloadKindScript
	}
	return types.WorkloadKindUnknown
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
