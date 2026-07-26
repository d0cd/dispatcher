package risk

import "github.com/d0cd/dispatcher/internal/types"

// Analyze enumerates risks for a workload on a target. spot indicates the run
// requested an interruptible instance, which carries its own reclaim risk.
func Analyze(w types.WorkloadSpec, t types.TargetConfig, est types.CostEstimate, spot bool) []types.Risk {
	var risks []types.Risk

	// Spot/preemptible interruption: the provider can reclaim the instance at any
	// time, killing the run mid-flight. Only safe for restartable work.
	if spot {
		risks = append(risks, types.Risk{
			Category:    "spot-interruption",
			Description: "spot/preemptible instance can be reclaimed by the provider at any time; the run may be interrupted mid-execution — only for restartable work, and pair with --retry-transient to auto re-provision (typical GPU reclaim: A100 ~15-20%, H100 <5%)",
		})
	}

	// Cost uncertainty
	if est.Confidence == types.ConfidenceLow || est.Confidence == types.ConfidenceUnknown {
		risks = append(risks, types.Risk{
			Category:    "cost-uncertainty",
			Description: "cost estimate has low confidence; actual cost may differ significantly",
		})
	}

	// Runtime uncertainty
	if w.DetectedKind == types.WorkloadKindService {
		risks = append(risks, types.Risk{
			Category:    "runtime-uncertainty",
			Description: "runtime estimate is based on default assumptions for services",
		})
	}

	// GPU risks
	if w.Requirements.GPU.Required {
		risks = append(risks, types.Risk{
			Category:    "capacity-risk",
			Description: "GPU availability may be limited; job could be queued",
		})
		// Right-sizing warning: a GPU spec without a model matches the
		// cheapest GPU instance in the catalog, which is usually fine but
		// can pick a wrong-tier instance in regions with unusual inventory.
		// Concretely, "gpu.count: 1" alone routinely matches T4 or L4 when
		// the user expected an A100/H100. Flag it so reviewers notice.
		if w.Requirements.GPU.Model == "" {
			risks = append(risks, types.Risk{
				Category:    "right-sizing",
				Description: "GPU spec has no model — planner picks the cheapest GPU instance, which may not match your performance expectation; set gpu.model (e.g. h100, a100, t4) to pin the tier",
			})
		}
		// No catalog instance matched the GPU requirement on this cloud target,
		// so `dispatcher run` will refuse to provision rather than silently use a
		// CPU box. Surface it here so the user learns at plan time, not run time.
		if t.Kind == types.TargetKindCloudVM && est.InstanceType == "" {
			risks = append(risks, types.Risk{
				Category:    "gpu-unschedulable",
				Description: "no catalog instance matches the required GPU on this target; `dispatcher run` will refuse to provision — pin a supported gpu.model or choose a provider with GPU inventory",
			})
		}
	}

	// Secret access risks
	if len(w.Secrets) > 0 {
		risks = append(risks, types.Risk{
			Category:    "credential-risk",
			Description: "workload references secrets that must be configured on the target",
		})
	}

	// Data risks
	for _, d := range w.Data {
		if d.Kind == "s3" || d.Kind == "gcs" {
			risks = append(risks, types.Risk{
				Category:    "data-egress-risk",
				Description: "data in " + d.Details + " may incur egress cost if target is in a different region",
			})
		}
		if d.Kind == "database" {
			risks = append(risks, types.Risk{
				Category:    "network-access-risk",
				Description: "workload requires database access; target must have private network connectivity",
			})
		}
	}

	// Public endpoint risk
	if w.DetectedKind == types.WorkloadKindService && t.Capabilities.Networking.PublicEndpoint {
		risks = append(risks, types.Risk{
			Category:    "public-endpoint-risk",
			Description: "public endpoint exposure requires approval",
		})
	}

	// Package/build risk
	if w.Package.BuildRequired && w.Package.Dockerfile == "" {
		risks = append(risks, types.Risk{
			Category:    "package-risk",
			Description: "no Dockerfile found; container image must be generated, which may fail",
		})
	}

	// Confidential disk-at-rest residual (N1 in docs/confidential-computing.md):
	// a confidential VM hardware-encrypts memory, but the OS disk is not
	// host-opaque on these providers (cloud-KMS / VMGuestStateOnly), so durable
	// secrets written to disk remain readable by the cloud. Keep secrets in memory.
	if w.Requirements.Confidential.Required {
		risks = append(risks, types.Risk{
			Category:    "confidential-disk-residual",
			Description: "confidential VM encrypts memory, but the OS disk is not yet host-opaque (confidential OS-disk encryption is not wired) — keep durable secrets in memory (see docs/confidential-computing.md, N1)",
		})
	}

	// Declared outputs on a target whose adapter can't retrieve them are silently
	// lost: the docker and kubernetes adapters return no artifacts and tear the
	// container/pod down after the run, so anything the workload wrote is gone.
	if len(w.Outputs) > 0 && (t.Kind == types.TargetKindDocker || t.Kind == types.TargetKindKubernetes) {
		risks = append(risks, types.Risk{
			Category:    "outputs-unretrievable",
			Description: "workload declares outputs: but the " + string(t.Kind) + " target does not retrieve artifacts and tears the container/pod down after the run — declared results will be lost; use an ssh or cloud-vm target to collect them",
		})
	}

	return risks
}
