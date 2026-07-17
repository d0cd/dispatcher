package cloudvm

import (
	"context"
	"time"
)

// ProviderID identifies a cloud provider.
type ProviderID string

const (
	ProviderHetzner    ProviderID = "hetzner"
	ProviderAWS        ProviderID = "aws"
	ProviderGCP        ProviderID = "gcp"
	ProviderAzure      ProviderID = "azure"
	ProviderLima       ProviderID = "lima"
	ProviderKubernetes ProviderID = "kubernetes"
	ProviderOCI        ProviderID = "oci"
	ProviderLambda     ProviderID = "lambda"
)

// VMOptions describes the VM to create.
type VMOptions struct {
	Name         string
	InstanceType string
	Region       string
	Image        string
	SSHKeyPath   string
	// SSHUser is the login the provider must authorize the SSH key for. GCP
	// binds it in ssh-keys metadata; AWS folds it into the boot user-data.
	SSHUser  string
	UserData string            // cloud-init script
	Tags     map[string]string // must include dispatcher-run-id
	// AllowSSHFrom, when a non-empty CIDR, requests a per-run firewall that
	// permits inbound SSH only from that range. Empty = no firewall.
	AllowSSHFrom string
	// MaxLifetimeSeconds is an absolute upper bound on the resource's lifetime
	// (from the run's MaxDuration). Zero = no hard cap. On Kubernetes it becomes
	// the Job's activeDeadlineSeconds.
	MaxLifetimeSeconds int
	// Command is the workload shell command. On Kubernetes it runs as the Job's
	// main container so the Job's success/failure reflects the workload's exit.
	Command string
	// GPUCount, when > 0, requests that many GPUs. On Kubernetes it becomes the
	// container's nvidia.com/gpu resource limit.
	GPUCount int
	// ConfidentialType, when non-empty ("sev" | "sev-snp" | "tdx" | "any"),
	// requests a TEE-backed (memory-encrypted) VM of that type. The provider
	// maps it to its create flag and rejects it where unsupported.
	ConfidentialType string
	// ConfidentialSpaceImage, when non-empty, requests a GCP Confidential Space
	// container VM that launches this image reference (the measured workload) via
	// tee-image-reference — a distinct provisioning mode from a plain SSH VM.
	ConfidentialSpaceImage string
	// ConfidentialAllowFrom, when a non-empty CIDR, requests a firewall opening
	// the in-TEE agent's port (8443) only to that range (dispatcher's egress IP).
	// The untrusted-channel design makes the endpoint safe to expose, but scoping
	// it is defense-in-depth against unsolicited traffic.
	ConfidentialAllowFrom string
	// EnclaveEnabled requests a Nitro Enclaves-capable parent instance (AWS
	// --enclave-options Enabled=true). The parent itself is not memory-encrypted;
	// the measured enclave it launches is the TEE. Distinct from ConfidentialType.
	EnclaveEnabled bool
	// SecureBootDisabled turns Secure Boot off on a confidential VM. The Azure
	// direct SNP+vTPM measured path uses an unsigned custom UKI image, which needs
	// Secure Boot off; attestation there rests on PCR11, not Secure Boot.
	SecureBootDisabled bool
}

// VMInfo describes a provisioned VM.
type VMInfo struct {
	ID   string
	Name string
	IP   string
	// SSHPort is non-zero when the provider exposes SSH on a non-standard
	// port (Lima forwards to 127.0.0.1:<random>). Cloud VMs leave it 0 and
	// the adapter defaults to 22.
	SSHPort int
	// SSHKeyPath, when non-empty, is a path to a private key that the
	// provider has pre-authorized for the VM. Cloud-VM providers (AWS,
	// GCP, Azure, Hetzner) leave this empty — the adapter generates a
	// per-run ed25519 key and injects the pub via cloud-init. Lima sets
	// it to ~/.lima/_config/user since Lima manages its own SSH identity.
	SSHKeyPath string
	// SSHUser, when non-empty, is the username the provider expects on the
	// VM. Lima uses the host user's name; cloud VMs use a provider-
	// specific default ("ubuntu", "ec2-user", "dispatcher", etc.) and let
	// the adapter Config supply it.
	SSHUser   string
	State     VMState
	CreatedAt time.Time
	Tags      map[string]string
}

// VMState represents the VM lifecycle state.
type VMState string

const (
	VMStatePending    VMState = "pending"
	VMStateRunning    VMState = "running"
	VMStateStopping   VMState = "stopping"
	VMStateTerminated VMState = "terminated"
	VMStateError      VMState = "error"
)

// Provider abstracts cloud provider CLI operations.
type Provider interface {
	// Name returns the provider identifier.
	Name() ProviderID

	// CheckCLI verifies the provider CLI is installed and authenticated.
	CheckCLI(ctx context.Context) error

	// CreateVM provisions a new VM.
	CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error)

	// WaitReady blocks until the VM is SSH-reachable.
	WaitReady(ctx context.Context, vmID string, ip string, keyPath string) error

	// GetVM returns current VM information. Contract: if the VM no longer
	// exists (a "not found" describe result), return &VMInfo{State:
	// VMStateTerminated}, nil — absence is a definitive state, not an error.
	// Every other failure (transient/API/auth) propagates as an error so a
	// caller doesn't mistake a blip for a terminated VM.
	GetVM(ctx context.Context, vmID string) (*VMInfo, error)

	// DestroyVM terminates and deletes the VM.
	DestroyVM(ctx context.Context, vmID string) error

	// ListVMs returns all VMs with matching tags.
	ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error)
}
