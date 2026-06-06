package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
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

func (a *AzureProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	location := opts.Region
	if location == "" {
		location = a.location
	}
	instanceType := opts.InstanceType
	if instanceType == "" {
		instanceType = "Standard_B2s"
	}
	image := opts.Image
	if image == "" {
		image = "Canonical:ubuntu-24_04-lts:server:latest"
	}

	args := []string{
		"vm", "create",
		"--resource-group", a.resourceGroup,
		"--name", opts.Name,
		"--location", location,
		"--size", instanceType,
		"--image", image,
		"--admin-username", "dispatcher",
		"--generate-ssh-keys",
		"--output", "json",
	}

	if opts.UserData != "" {
		args = append(args, "--custom-data", opts.UserData)
	}

	// Azure tags
	if len(opts.Tags) > 0 {
		tagArgs := ""
		for k, v := range opts.Tags {
			if tagArgs != "" {
				tagArgs += " "
			}
			tagArgs += fmt.Sprintf("%s=%s", k, v)
		}
		args = append(args, "--tags", tagArgs)
	}

	cmd := exec.CommandContext(ctx, "az", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("az vm create failed: %w", err)
	}

	var result struct {
		ID              string `json:"id"`
		PublicIpAddress  string `json:"publicIpAddress"`
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

func (a *AzureProvider) WaitReady(ctx context.Context, _ string, ip string, _ string) error {
	return WaitForSSH(ctx, ip, 5*time.Minute)
}

func (a *AzureProvider) GetVM(ctx context.Context, vmID string) (*VMInfo, error) {
	cmd := exec.CommandContext(ctx, "az", "vm", "show",
		"--resource-group", a.resourceGroup,
		"--name", vmID,
		"--show-details",
		"--output", "json",
	)
	output, err := cmd.Output()
	if err != nil {
		return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
	}

	var result struct {
		Name           string `json:"name"`
		PowerState     string `json:"powerState"`
		PublicIps      string `json:"publicIps"`
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
	cmd := exec.CommandContext(ctx, "az", "vm", "delete",
		"--resource-group", a.resourceGroup,
		"--name", vmID,
		"--yes",
		"--force-deletion", "true",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("az vm delete failed: %w", err)
	}
	return nil
}

func (a *AzureProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	args := []string{"vm", "list",
		"--resource-group", a.resourceGroup,
		"--show-details",
		"--output", "json",
	}

	cmd := exec.CommandContext(ctx, "az", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("az vm list failed: %w", err)
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
