package target

import (
	"runtime"
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
		} else if m := w.Requirements.GPU.Model; m != "" {
			// A specific model was requested. A target that advertises GPU support
			// but enumerates no models can't confirm it — fail closed rather than
			// accept any model (which would recommend a target that can't run it).
			if len(gpu.Models) == 0 {
				reasons = append(reasons, "GPU model "+m+" requested but target lists no specific GPU models")
			} else if !offersGPUModel(gpu.Models, m) {
				reasons = append(reasons, "GPU model "+m+" not offered by target (offers: "+strings.Join(gpu.Models, ", ")+")")
			}
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
		// Confidential and GPU together are unsupported: every confidential backend
		// provisions a CPU-only CVM (there is no confidential GPU SKU), so the run
		// path would silently drop the GPU requirement. Fail closed at plan time
		// rather than billing a confidential VM that can't run the GPU job.
		if w.Requirements.GPU.Required {
			reasons = append(reasons, "confidential GPU workloads are not supported (confidential backends provision CPU-only VMs)")
		}
		// A measured-boot profile is provider-specific — it may only run on the
		// matching provider's target, so the plan can't recommend a cross-cloud
		// target that would silently route to an unmeasured backend.
		if req := RequiredTargetForProfile(c.Profile); req != "" && t.ID != req {
			reasons = append(reasons, "confidential profile "+c.Profile+" requires target "+req)
		}
		// An attested run (attestation != off) needs the target's MEASURED backend:
		// the standard SEV-SNP / MAA agents aren't in the launch measurement, so the
		// run path refuses them. Feasibility must agree or the plan recommends a
		// target run will reject. GCP Confidential Space needs no explicit profile.
		if !strings.EqualFold(c.Attestation, "off") {
			switch t.ID {
			case "aws-vm":
				if c.Profile != "nitro" {
					reasons = append(reasons, "confidential attestation on aws-vm requires profile: nitro (the standard SEV-SNP agent is unmeasured)")
				}
			case "azure-vm":
				if c.Profile != "azure-snp" {
					reasons = append(reasons, "confidential attestation on azure-vm requires profile: azure-snp (the standard MAA agent is unmeasured)")
				}
			}
		}
	}

	// Architecture: a host-bound target (this machine) can only run the host's
	// arch, so an arch-constrained workload that doesn't match is infeasible here.
	// Cloud VMs pick a matching instance arch later, so they're not gated here.
	if a := normalizeArch(w.Requirements.Arch); a != "" && isHostBound(t.Kind) && a != normalizeArch(runtime.GOARCH) {
		reasons = append(reasons, "workload requires "+a+" but target runs on the host architecture "+normalizeArch(runtime.GOARCH))
	}

	// Sandbox requires isolation stronger than a bare host process (container or
	// VM level), so a process-only target (local-process) is infeasible.
	if w.Requirements.Sandbox && !offersIsolation(t.Capabilities.Isolation.Levels) {
		reasons = append(reasons, "sandbox required but target only offers process-level isolation")
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

// isHostBound reports whether a target kind runs on dispatcher's own host (so it
// is fixed to the host architecture). SSH/cloud/k8s targets run elsewhere and
// have their arch validated at provisioning, not here.
func isHostBound(k types.TargetKind) bool {
	switch k {
	case types.TargetKindLocal, types.TargetKindDocker, types.TargetKindLocalVM:
		return true
	default:
		return false
	}
}

// normalizeArch folds common architecture spellings to a canonical token so an
// "x86_64" workload matches an "amd64" host.
func normalizeArch(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "amd64", "x86_64", "x86-64", "x64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(a))
	}
}

// offersIsolation reports whether a target provides isolation stronger than a
// bare host process (container or VM level) — what a sandboxed workload needs.
func offersIsolation(levels []string) bool {
	for _, l := range levels {
		if l != "" && !strings.EqualFold(l, "process") {
			return true
		}
	}
	return false
}

// offersGPUModel reports whether a target offers the requested GPU model,
// case-insensitively — the pricing catalog matches models with EqualFold, so
// feasibility must agree or `model: A100` is spuriously rejected.
func offersGPUModel(models []string, m string) bool {
	for _, x := range models {
		if strings.EqualFold(x, m) {
			return true
		}
	}
	return false
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
