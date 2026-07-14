package target

import (
	"strings"

	"github.com/d0cd/dispatcher/internal/types"
)

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
	if w.Requirements.GPU.Required {
		gpu := t.Capabilities.Resources.GPU
		if !gpu.Supported {
			reasons = append(reasons, "GPU required but target does not support GPU")
		} else if m := w.Requirements.GPU.Model; m != "" && len(gpu.Models) > 0 && !inSlice(gpu.Models, m) {
			reasons = append(reasons, "GPU model "+m+" not offered by target (offers: "+strings.Join(gpu.Models, ", ")+")")
		}
	}

	// Check confidential-computing requirements
	if c := w.Requirements.Confidential; c.Required {
		conf := t.Capabilities.Resources.Confidential
		if !conf.Supported {
			reasons = append(reasons, "confidential computing required but target does not support it")
		} else if c.Type != "" && c.Type != "any" && !inSlice(conf.Types, c.Type) {
			reasons = append(reasons, "confidential type "+c.Type+" not offered by target (offers: "+strings.Join(conf.Types, ", ")+")")
		}
		// A measured-boot profile is provider-specific — it may only run on the
		// matching provider's target, so the plan can't recommend a cross-cloud
		// target that would silently route to an unmeasured backend.
		if req := RequiredTargetForProfile(c.Profile); req != "" && t.ID != req {
			reasons = append(reasons, "confidential profile "+c.Profile+" requires target "+req)
		}
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

// RequiredTargetForProfile maps a measured-boot confidential profile to the
// only target ID it can run on. Empty profile (the standard backend) returns "".
func RequiredTargetForProfile(profile string) string {
	switch profile {
	case "nitro":
		return "aws-vm"
	case "azure-snp":
		return "azure-vm"
	default:
		return ""
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
	case types.TargetKindCloudVM:
		return "cloud-vm"
	default:
		return string(t.Kind)
	}
}
