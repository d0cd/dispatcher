package target

import "github.com/d0cd/dispatcher/internal/types"

// FeasibilityResult describes whether a target can run a workload.
type FeasibilityResult struct {
	Feasible bool
	Reasons  []string
}

// CheckFeasibility evaluates whether a target can run the given workload.
func CheckFeasibility(t types.TargetConfig, w types.WorkloadSpec) FeasibilityResult {
	var reasons []string

	if !t.Enabled {
		return FeasibilityResult{Feasible: false, Reasons: []string{"target is disabled"}}
	}

	// Check workload kind support
	if !supportsKind(t.Capabilities.WorkloadKinds, w.DetectedKind) {
		reasons = append(reasons, "workload kind "+string(w.DetectedKind)+" not supported by target")
	}

	// Check GPU requirements
	if w.Requirements.GPU.Required && !t.Capabilities.Resources.GPU.Supported {
		reasons = append(reasons, "GPU required but target does not support GPU")
	}

	// Check service-specific requirements
	if w.DetectedKind == types.WorkloadKindService {
		for _, ns := range t.Capabilities.NotSupported {
			if ns == "long-running-service" {
				reasons = append(reasons, "target does not support long-running services")
			}
		}
	}

	return FeasibilityResult{
		Feasible: len(reasons) == 0,
		Reasons:  reasons,
	}
}

func supportsKind(supported []types.WorkloadKind, kind types.WorkloadKind) bool {
	for _, k := range supported {
		if k == kind {
			return true
		}
	}
	return false
}

// RuntimeForTarget returns the runtime string for a target kind.
func RuntimeForTarget(t types.TargetConfig) string {
	switch t.Kind {
	case types.TargetKindLocal:
		return "local-process"
	case types.TargetKindLocalVM:
		return "local-vm"
	case types.TargetKindDocker:
		return "local-docker"
	case types.TargetKindSSH:
		return "ssh-remote"
	case types.TargetKindKubernetes:
		return "kubernetes-deployment"
	case types.TargetKindModal:
		return "managed-service"
	case types.TargetKindE2B:
		return "managed-sandbox"
	case types.TargetKindCloudVM:
		return "cloud-vm"
	default:
		return string(t.Kind)
	}
}
