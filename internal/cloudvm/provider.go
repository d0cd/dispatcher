package cloudvm

import (
	"context"
	"time"
)

// ProviderID identifies a cloud provider.
type ProviderID string

const (
	ProviderHetzner   ProviderID = "hetzner"
	ProviderAWS       ProviderID = "aws"
	ProviderGCP       ProviderID = "gcp"
	ProviderAzure     ProviderID = "azure"
	ProviderMultipass   ProviderID = "multipass"
	ProviderLima        ProviderID = "lima"
	ProviderKubernetes  ProviderID = "kubernetes"
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
}

// VMInfo describes a provisioned VM.
type VMInfo struct {
	ID        string
	Name      string
	IP        string
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
