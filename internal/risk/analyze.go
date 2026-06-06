package risk

import "github.com/d0cd/dispatcher/internal/types"

// Analyze enumerates risks for a workload on a target.
func Analyze(w types.WorkloadSpec, t types.TargetConfig, est types.CostEstimate) []types.Risk {
	var risks []types.Risk

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

	return risks
}
