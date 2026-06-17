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
)

// VMOptions describes the VM to create.
type VMOptions struct {
	Name         string
	InstanceType string
	Region       string
	Image        string
	SSHKeyPath   string
	UserData     string            // cloud-init script
	Tags         map[string]string // must include dispatcher-run-id
	// AllowSSHFrom, when a non-empty CIDR, requests a per-run firewall that
	// permits inbound SSH only from that range. Empty = no firewall.
	AllowSSHFrom string
	// WatchdogTTLSeconds is the renewable self-destruct window for targets that
	// run an in-pod/in-VM watchdog (currently Kubernetes). Zero = adapter default.
	WatchdogTTLSeconds int
	// MaxLifetimeSeconds is an absolute upper bound on the resource's lifetime
	// (from the run's MaxDuration), independent of watchdog renewal. Zero = none.
	MaxLifetimeSeconds int
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

	// GetVM returns current VM information.
	GetVM(ctx context.Context, vmID string) (*VMInfo, error)

	// DestroyVM terminates and deletes the VM.
	DestroyVM(ctx context.Context, vmID string) error

	// ListVMs returns all VMs with matching tags.
	ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error)
}
