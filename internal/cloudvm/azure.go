package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// AzureProvider implements Provider using the az CLI.
type AzureProvider struct {
	resourceGroup string
	location      string
}

// NewAzureProvider creates an Azure provider.
func NewAzureProvider(resourceGroup, location string) *AzureProvider {
	if location == "" {
		location = "eastus"
	}
	return &AzureProvider{
		resourceGroup: resourceGroup,
		location:      location,
	}
}

func (a *AzureProvider) Name() ProviderID { return ProviderAzure }

// SetRegion re-points the provider's location (Azure's region name).
func (a *AzureProvider) SetRegion(region string) {
	if region != "" {
		a.location = region
	}
}

func (a *AzureProvider) CheckCLI(ctx context.Context) error {
	if _, err := exec.LookPath("az"); err != nil {
		return fmt.Errorf("az CLI not found: %w", err)
	}
	cmd := exec.CommandContext(ctx, "az", "account", "show")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("az not authenticated: %w", err)
	}
	return nil
}

// azureConfidentialArgs returns the vm-create flags for a confidential VM (or
// nil for non-confidential). Azure Confidential VMs are SEV-SNP (DCasv5/ECasv5)
// or TDX (DCesv5/ECesv5) — selected by the VM size, so the create flag is
// type-agnostic; there's no plain-SEV offering. VMGuestStateOnly encrypts the
// guest state without requiring a customer disk-encryption set (the simpler
// default; not full host-opaque OS-disk encryption — see N1).
func azureConfidentialArgs(opts VMOptions) ([]string, error) {
	if opts.ConfidentialType == "" {
		return nil, nil
	}
	if opts.ConfidentialType == "sev" {
		return nil, fmt.Errorf("azure confidential VMs are sev-snp or tdx (chosen by SKU), not plain sev")
	}
	secureBoot := "true"
	if opts.SecureBootDisabled {
		secureBoot = "false"
	}
	return []string{
		"--security-type", "ConfidentialVM",
		"--enable-vtpm", "true",
		"--enable-secure-boot", secureBoot,
		"--os-disk-security-encryption-type", "VMGuestStateOnly",
	}, nil
}

func (a *AzureProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	location := opts.Region
	if location == "" {
		location = a.location
	}
	instanceType := opts.InstanceType
	if instanceType == "" {
		instanceType = "Standard_B2s"
		if opts.ConfidentialType != "" {
			// B-series can't do confidential; DCadsv5 is AMD SEV-SNP capable.
			instanceType = "Standard_DC2ads_v5"
		}
	}
	image := opts.Image
	if image == "" {
		image = "Canonical:ubuntu-24_04-lts:server:latest"
		if opts.ConfidentialType != "" {
			// Confidential VMs require the CVM-generation image (separate SKU),
			// not the plain server image.
			image = "Canonical:ubuntu-24_04-lts:cvm:latest"
		}
	}
	if err := validateVMArgs(location, instanceType, image); err != nil {
		return nil, fmt.Errorf("azure: %w", err)
	}
	if opts.AllowSSHFrom != "" {
		return nil, errFirewallUnsupported("azure")
	}

	args := []string{
		"vm", "create",
		"--resource-group", a.resourceGroup,
		"--name", opts.Name,
		"--location", location,
		"--size", instanceType,
		"--image", image,
		"--admin-username", "dispatcher",
		"--output", "json",
	}
	// Inject dispatcher's per-run public key. --generate-ssh-keys would make
	// Azure mint (or reuse ~/.ssh) a key dispatcher doesn't hold, so it could
	// never SSH into the VM.
	if opts.SSHKeyPath != "" {
		args = append(args, "--ssh-key-values", opts.SSHKeyPath)
	} else {
		args = append(args, "--generate-ssh-keys")
	}

	confArgs, err := azureConfidentialArgs(opts)
	if err != nil {
		return nil, err
	}
	args = append(args, confArgs...)

	if opts.UserData != "" {
		// Azure CLI's `--custom-data @<path>` reads from a file. Keeps the
		// (potentially large, potentially shell-special) blob entirely off
		// argv where `ps` would otherwise show it.
		path, err := adapter.WriteSecureTempFile("dispatcher-azure-userdata-*.sh", []byte(opts.UserData))
		if err != nil {
			return nil, fmt.Errorf("write user-data: %w", err)
		}
		defer os.Remove(path)
		args = append(args, "--custom-data", "@"+path)
	}

	// Azure tags: az CLI's `--tags` accepts repeated `key=value` arguments
	// AFTER the flag — separate argv elements, no joining. The previous
	// space-joined single-string form was a flag-injection vector if any
	// value contained a space. Validation rejects metacharacters before we
	// hit the CLI at all.
	if err := validateLabels(opts.Tags); err != nil {
		return nil, fmt.Errorf("azure tags: %w", err)
	}
	if len(opts.Tags) > 0 {
		args = append(args, "--tags")
		for k, v := range opts.Tags {
			args = append(args, k+"="+v)
		}
	}

	output, err := retryCLIOutput(ctx, "az", "az vm create", args...)
	if err != nil {
		// az masks a NotAvailableForSubscription error as a "content already
		// consumed" CLI crash. Only in that case, probe the SKU to surface the
		// real, actionable reason instead of the opaque crash.
		if strings.Contains(err.Error(), "already consumed") {
			if ok, reason := azureSKUAvailable(ctx, location, instanceType); !ok {
				return nil, fmt.Errorf("azure: VM size %s is %s in %s — choose a different --size or region: %w",
					instanceType, reason, location, err)
			}
		}
		return nil, err
	}

	var result struct {
		ID              string `json:"id"`
		PublicIpAddress string `json:"publicIpAddress"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("cannot parse az output: %w", err)
	}

	return &VMInfo{
		ID:        opts.Name, // Azure uses name for most operations
		Name:      opts.Name,
		IP:        result.PublicIpAddress,
		State:     VMStateRunning,
		CreatedAt: time.Now().UTC(),
		Tags:      opts.Tags,
	}, nil
}

// azureSKUAvailable reports whether the VM size is orderable in the location for
// this subscription. Returns (true, "") when available or when the check itself
// can't run (best-effort — never block a create on an inconclusive probe).
func azureSKUAvailable(ctx context.Context, location, size string) (bool, string) {
	out, err := runCLI(ctx, "az", "vm", "list-skus",
		"--location", location, "--size", size,
		"--resource-type", "virtualMachines", "--all", "--output", "json")
	if err != nil {
		return true, ""
	}
	var skus []struct {
		Name         string `json:"name"`
		Restrictions []struct {
			ReasonCode string `json:"reasonCode"`
		} `json:"restrictions"`
	}
	if json.Unmarshal(out, &skus) != nil {
		return true, ""
	}
	for _, s := range skus {
		if s.Name != size {
			continue
		}
		for _, r := range s.Restrictions {
			if r.ReasonCode == "NotAvailableForSubscription" {
				return false, "not available for this subscription"
			}
			if r.ReasonCode != "" {
				return false, r.ReasonCode
			}
		}
		return true, ""
	}
	return true, "" // size not in the filtered list; don't block
}

func (a *AzureProvider) WaitReady(ctx context.Context, _ string, ip string, _ string) error {
	return WaitForSSH(ctx, ip, 5*time.Minute)
}

func (a *AzureProvider) GetVM(ctx context.Context, vmID string) (*VMInfo, error) {
	output, err := runCLI(ctx, "az", "vm", "show",
		"--resource-group", a.resourceGroup,
		"--name", vmID,
		"--show-details",
		"--output", "json",
	)
	if err != nil {
		return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
	}

	var result struct {
		Name       string `json:"name"`
		PowerState string `json:"powerState"`
		PublicIps  string `json:"publicIps"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	state := VMStateRunning
	if result.PowerState == "VM deallocated" || result.PowerState == "VM stopped" {
		state = VMStateTerminated
	}

	return &VMInfo{
		ID:    vmID,
		Name:  result.Name,
		IP:    result.PublicIps,
		State: state,
	}, nil
}

func (a *AzureProvider) DestroyVM(ctx context.Context, vmID string) error {
	// `az vm delete` removes only the VM resource, leaving its auto-created OS
	// disk, NIC, public IP, and NSG behind — the disk and IP keep billing.
	// Capture their ids before deleting the VM, then cascade-delete them in
	// dependency order so teardown doesn't leak.
	assoc := a.gatherVMResources(ctx, vmID)

	if _, err := runCLI(ctx, "az", "vm", "delete",
		"--resource-group", a.resourceGroup,
		"--name", vmID,
		"--yes",
		"--force-deletion", "true",
	); err != nil {
		return fmt.Errorf("az vm delete failed: %w", err)
	}

	a.deleteAssociatedResources(ctx, assoc)
	return nil
}

func (a *AzureProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	args := []string{"vm", "list",
		"--resource-group", a.resourceGroup,
		"--show-details",
		"--output", "json",
	}

	output, err := runCLI(ctx, "az", args...)
	if err != nil {
		return nil, wrapExecError("az vm list", err)
	}

	var vms []struct {
		Name       string            `json:"name"`
		PowerState string            `json:"powerState"`
		Tags       map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(output, &vms); err != nil {
		return nil, err
	}

	var result []VMInfo
	for _, vm := range vms {
		// Filter by tags
		match := true
		for k, v := range tags {
			if vm.Tags[k] != v {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if vm.PowerState == "VM deallocated" {
			continue
		}
		result = append(result, VMInfo{
			ID:    vm.Name,
			Name:  vm.Name,
			State: VMStateRunning,
			Tags:  vm.Tags,
		})
	}
	return result, nil
}
