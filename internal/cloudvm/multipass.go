package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// MultipassProvider implements Provider using the multipass CLI for local VMs.
type MultipassProvider struct{}

// NewMultipassProvider creates a new Multipass provider.
func NewMultipassProvider() *MultipassProvider {
	return &MultipassProvider{}
}

func (m *MultipassProvider) Name() ProviderID { return ProviderMultipass }

func (m *MultipassProvider) CheckCLI(ctx context.Context) error {
	if _, err := exec.LookPath("multipass"); err != nil {
		return fmt.Errorf("multipass CLI not found: %w", err)
	}
	cmd := exec.CommandContext(ctx, "multipass", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("multipass not working: %w", err)
	}
	return nil
}

func (m *MultipassProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	instanceType := opts.InstanceType
	if instanceType == "" {
		instanceType = "2,2G,10G" // 2 CPUs, 2GB RAM, 10GB disk
	}

	// Parse instance type as "cpus,mem,disk"
	parts := strings.SplitN(instanceType, ",", 3)
	cpus := "2"
	mem := "2G"
	disk := "10G"
	if len(parts) >= 1 && parts[0] != "" {
		cpus = parts[0]
	}
	if len(parts) >= 2 && parts[1] != "" {
		mem = parts[1]
	}
	if len(parts) >= 3 && parts[2] != "" {
		disk = parts[2]
	}

	args := []string{
		"launch",
		"--name", opts.Name,
		"--cpus", cpus,
		"--memory", mem,
		"--disk", disk,
	}

	if opts.UserData != "" {
		args = append(args, "--cloud-init", "-")
	}

	cmd := exec.CommandContext(ctx, "multipass", args...)
	if opts.UserData != "" {
		cmd.Stdin = strings.NewReader(opts.UserData)
	}

	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("multipass launch failed: %s: %w", string(output), err)
	}

	// Get the VM's IP
	ip, err := m.getIP(ctx, opts.Name)
	if err != nil {
		_ = m.DestroyVM(ctx, opts.Name)
		return nil, fmt.Errorf("cannot get VM IP: %w", err)
	}

	return &VMInfo{
		ID:        opts.Name,
		Name:      opts.Name,
		IP:        ip,
		State:     VMStateRunning,
		CreatedAt: time.Now().UTC(),
		Tags:      opts.Tags,
	}, nil
}

func (m *MultipassProvider) WaitReady(ctx context.Context, _ string, ip string, _ string) error {
	return WaitForSSH(ctx, ip, 3*time.Minute)
}

func (m *MultipassProvider) GetVM(ctx context.Context, vmID string) (*VMInfo, error) {
	cmd := exec.CommandContext(ctx, "multipass", "info", vmID, "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
	}

	var result struct {
		Info map[string]struct {
			State string   `json:"state"`
			IPv4  []string `json:"ipv4"`
		} `json:"info"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("cannot parse multipass info: %w", err)
	}

	info, ok := result.Info[vmID]
	if !ok {
		return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
	}

	state := VMStateRunning
	switch strings.ToLower(info.State) {
	case "running":
		state = VMStateRunning
	case "stopped", "suspended":
		state = VMStateStopping
	case "deleted":
		state = VMStateTerminated
	}

	ip := ""
	if len(info.IPv4) > 0 {
		ip = info.IPv4[0]
	}

	return &VMInfo{
		ID:    vmID,
		Name:  vmID,
		IP:    ip,
		State: state,
	}, nil
}

func (m *MultipassProvider) DestroyVM(ctx context.Context, vmID string) error {
	// Delete and purge
	cmd := exec.CommandContext(ctx, "multipass", "delete", vmID, "--purge")
	if err := cmd.Run(); err != nil {
		// Try force stop then delete
		_ = exec.CommandContext(ctx, "multipass", "stop", vmID).Run()
		cmd = exec.CommandContext(ctx, "multipass", "delete", vmID, "--purge")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("multipass delete failed: %w", err)
		}
	}
	return nil
}

func (m *MultipassProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	cmd := exec.CommandContext(ctx, "multipass", "list", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("multipass list failed: %w", err)
	}

	var result struct {
		List []struct {
			Name  string   `json:"name"`
			State string   `json:"state"`
			IPv4  []string `json:"ipv4"`
		} `json:"list"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	var vms []VMInfo
	for _, vm := range result.List {
		// Multipass doesn't support tags natively — filter by name prefix
		if !strings.HasPrefix(vm.Name, "dispatcher-") {
			continue
		}
		if strings.ToLower(vm.State) == "deleted" {
			continue
		}
		ip := ""
		if len(vm.IPv4) > 0 {
			ip = vm.IPv4[0]
		}
		vms = append(vms, VMInfo{
			ID:    vm.Name,
			Name:  vm.Name,
			IP:    ip,
			State: VMState(strings.ToLower(vm.State)),
			Tags:  map[string]string{"dispatcher": "true"},
		})
	}
	return vms, nil
}

func (m *MultipassProvider) getIP(ctx context.Context, name string) (string, error) {
	// Poll for IP (multipass assigns IP after boot)
	deadline := time.After(60 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline:
			return "", fmt.Errorf("timeout waiting for multipass VM IP")
		case <-ticker.C:
			vm, err := m.GetVM(ctx, name)
			if err == nil && vm.IP != "" {
				return vm.IP, nil
			}
		}
	}
}
