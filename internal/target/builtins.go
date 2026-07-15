package target

import (
	"os"

	"github.com/d0cd/dispatcher/internal/types"
)

// ociExperimentalEnabled reports whether the unvalidated OCI target is opted in.
// OCI provisioning is implemented but has never completed a live-tenancy
// validation (its `oci` argv, confidential platform-config, and SEV-SNP signing
// model are unverified), so it is disabled by default and enabled only via
// DISPATCHER_OCI_EXPERIMENTAL — the escape hatch for running that validation.
func ociExperimentalEnabled() bool {
	return os.Getenv("DISPATCHER_OCI_EXPERIMENTAL") != ""
}

// BuiltinTargets returns the built-in target definitions.
func BuiltinTargets() []types.TargetConfig {
	return []types.TargetConfig{
		{
			ID:      "local-process",
			Kind:    types.TargetKindLocal,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					GPU:    types.GPUCapability{Supported: false},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   false,
					PrivateVPCAccess: false,
					StaticEgressIP:   false,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: false,
					RateCard:      "local",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"process"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   false,
					Artifacts: false,
				},
			},
		},
		{
			ID:      "local-docker",
			Kind:    types.TargetKindDocker,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
					types.WorkloadKindContainer,
					types.WorkloadKindService,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					GPU:    types.GPUCapability{Supported: false},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   false,
					PrivateVPCAccess: false,
					StaticEgressIP:   false,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: false,
					RateCard:      "local",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"container"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   false,
					Artifacts: true,
				},
			},
		},
		{
			ID:      "lima-vm",
			Kind:    types.TargetKindLocalVM,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
					types.WorkloadKindContainer,
					types.WorkloadKindService,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					GPU:    types.GPUCapability{Supported: false},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   false,
					PrivateVPCAccess: false,
					StaticEgressIP:   false,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: false,
					RateCard:      "local",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"vm"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   false,
					Artifacts: true,
				},
			},
		},
		{
			// Local Firecracker microVMs: a KVM-backed local backend for fast,
			// isolated short jobs. Requires a Linux host with /dev/kvm.
			ID:      "firecracker-vm",
			Kind:    types.TargetKindLocalVM,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					GPU:    types.GPUCapability{Supported: false},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   false,
					PrivateVPCAccess: false,
					StaticEgressIP:   false,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: false,
					RateCard:      "local",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"vm"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   false,
					Artifacts: true,
				},
			},
		},
		{
			ID:      "ssh",
			Kind:    types.TargetKindSSH,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
					types.WorkloadKindContainer,
					types.WorkloadKindService,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					GPU:    types.GPUCapability{Supported: false},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   true,
					PrivateVPCAccess: true,
					StaticEgressIP:   false,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: false,
					RateCard:      "ssh",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"process", "container"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   false,
					Artifacts: true,
				},
			},
		},
		{
			ID:      "kubernetes",
			Kind:    types.TargetKindKubernetes,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
					types.WorkloadKindContainer,
					types.WorkloadKindService,
					types.WorkloadKindGPUJob,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					GPU: types.GPUCapability{
						Supported: true,
						Models:    []string{"a10", "l4"},
					},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   true,
					PrivateVPCAccess: true,
					StaticEgressIP:   false,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: false,
					RateCard:      "internal",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"container", "dedicated-node"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   true,
					Artifacts: true,
				},
			},
		},
		{
			ID:      "aws-vm",
			Kind:    types.TargetKindCloudVM,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
					types.WorkloadKindContainer,
					types.WorkloadKindService,
					types.WorkloadKindGPUJob,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					GPU: types.GPUCapability{
						Supported: true,
						Models:    []string{"t4", "a10g", "a100"},
					},
					Confidential: types.ConfidentialCapability{
						Supported: true,
						Types:     []string{"sev-snp"},
					},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   true,
					PrivateVPCAccess: true,
					StaticEgressIP:   true,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: true,
					RateCard:      "aws",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"vm"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   true,
					Artifacts: true,
				},
			},
		},
		{
			ID:      "gcp-vm",
			Kind:    types.TargetKindCloudVM,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
					types.WorkloadKindContainer,
					types.WorkloadKindService,
					types.WorkloadKindGPUJob,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					GPU: types.GPUCapability{
						Supported: true,
						Models:    []string{"l4", "a100", "h100"},
					},
					Confidential: types.ConfidentialCapability{
						Supported: true,
						// dispatcher's GCP confidential path is Confidential Space, which
						// provisions plain SEV — so a sev-snp/tdx request is rejected at
						// plan time rather than silently downgraded (use azure-snp / aws
						// for SEV-SNP). See internal/attest/confidential_space.go.
						Types: []string{"sev"},
					},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   true,
					PrivateVPCAccess: true,
					StaticEgressIP:   false,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: true,
					RateCard:      "gcp",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"vm"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   true,
					Artifacts: true,
				},
			},
		},
		{
			ID:      "azure-vm",
			Kind:    types.TargetKindCloudVM,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
					types.WorkloadKindContainer,
					types.WorkloadKindService,
					types.WorkloadKindGPUJob,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					GPU: types.GPUCapability{
						Supported: true,
						Models:    []string{"t4", "a100"},
					},
					Confidential: types.ConfidentialCapability{
						Supported: true,
						Types:     []string{"sev-snp", "tdx"},
					},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   true,
					PrivateVPCAccess: true,
					StaticEgressIP:   false,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: true,
					RateCard:      "azure",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"vm"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   true,
					Artifacts: true,
				},
			},
		},
		{
			ID:      "hetzner-vm",
			Kind:    types.TargetKindCloudVM,
			Enabled: true,
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
					types.WorkloadKindContainer,
					types.WorkloadKindService,
					types.WorkloadKindGPUJob,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					// Hetzner Cloud has no GPU server type (see the cloudvm catalog and
					// rate card, which carry no Hetzner GPU SKU). Advertising one would
					// let the planner price a GPU workload CPU-only and recommend a
					// target that run then refuses to provision.
					GPU: types.GPUCapability{Supported: false},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   true,
					PrivateVPCAccess: false,
					StaticEgressIP:   false,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: true,
					RateCard:      "hetzner",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"vm"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   false,
					Artifacts: true,
				},
			},
		},
		{
			ID:   "oci-vm",
			Kind: types.TargetKindCloudVM,
			// Experimental: implemented but not live-validated (see
			// ociExperimentalEnabled). Off by default so it's never auto-recommended
			// or run by accident; opt in with DISPATCHER_OCI_EXPERIMENTAL to validate
			// create → VNIC → SSH → cleanup → billing end to end.
			Enabled: ociExperimentalEnabled(),
			Capabilities: types.Capabilities{
				WorkloadKinds: []types.WorkloadKind{
					types.WorkloadKindScript,
					types.WorkloadKindJob,
					types.WorkloadKindContainer,
					types.WorkloadKindService,
				},
				Resources: types.ResourceCapability{
					CPU:    true,
					Memory: true,
					GPU:    types.GPUCapability{Supported: false},
					// OCI BYAS verification is not implemented. Do not advertise
					// confidential support or let planning treat encryption alone as
					// an attested secret-release boundary.
					Confidential: types.ConfidentialCapability{Supported: false},
				},
				Networking: types.NetworkingCapability{
					PublicEndpoint:   true,
					PrivateVPCAccess: true,
					StaticEgressIP:   true,
				},
				Accounting: types.AccountingCapability{
					CostEstimate:  true,
					ActualBilling: true,
					RateCard:      "oci",
				},
				Isolation: types.IsolationCapability{
					Levels: []string{"vm"},
				},
				Observability: types.ObservabilityCapability{
					Logs:      true,
					Metrics:   false,
					Artifacts: true,
				},
			},
		},
	}
}
