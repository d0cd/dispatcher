package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// LimaProvider implements Provider using the limactl CLI for local VMs.
type LimaProvider struct{}

// NewLimaProvider creates a new Lima provider.
func NewLimaProvider() *LimaProvider {
	return &LimaProvider{}
}

func (l *LimaProvider) Name() ProviderID { return ProviderLima }

func (l *LimaProvider) CheckCLI(ctx context.Context) error {
	if _, err := exec.LookPath("limactl"); err != nil {
		return fmt.Errorf("limactl CLI not found: %w", err)
	}
	cmd := exec.CommandContext(ctx, "limactl", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("limactl not working: %w", err)
	}
	return nil
}

func (l *LimaProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	args := []string{
		"create",
		"--name", opts.Name,
		"--tty=false",
	}

	// Lima uses YAML templates. Default to Ubuntu.
	template := "template://ubuntu-24.04"
	if opts.Image != "" {
		template = opts.Image
	}
	args = append(args, template)

	cmd := exec.CommandContext(ctx, "limactl", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("limactl create failed: %s: %w", string(output), err)
	}

	// Start the VM
	startCmd := exec.CommandContext(ctx, "limactl", "start", opts.Name)
	if output, err := startCmd.CombinedOutput(); err != nil {
		_ = l.DestroyVM(ctx, opts.Name)
		return nil, fmt.Errorf("limactl start failed: %s: %w", string(output), err)
	}

	// Get IP
	ip, err := l.getIP(ctx, opts.Name)
	if err != nil {
		_ = l.DestroyVM(ctx, opts.Name)
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

func (l *LimaProvider) WaitReady(ctx context.Context, _ string, ip string, _ string) error {
	return WaitForSSH(ctx, ip, 3*time.Minute)
}

func (l *LimaProvider) GetVM(ctx context.Context, vmID string) (*VMInfo, error) {
	cmd := exec.CommandContext(ctx, "limactl", "list", "--json")
	output, err := cmd.Output()
	if err != nil {
		return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
	}

	// limactl list --json outputs one JSON object per line
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var inst struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Config struct {
				Networks []struct {
					Interface string `json:"interface"`
				} `json:"networks"`
			} `json:"config"`
		}
		if err := json.Unmarshal([]byte(line), &inst); err != nil {
			continue
		}
		if inst.Name != vmID {
			continue
		}

		state := VMStateRunning
		switch inst.Status {
		case "Running":
			state = VMStateRunning
		case "Stopped":
			state = VMStateStopping
		default:
			state = VMStateTerminated
		}

		ip, _ := l.getIP(ctx, vmID)

		return &VMInfo{
			ID:    vmID,
			Name:  vmID,
			IP:    ip,
			State: state,
		}, nil
	}

	return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
}

func (l *LimaProvider) DestroyVM(ctx context.Context, vmID string) error {
	// Stop first
	_ = exec.CommandContext(ctx, "limactl", "stop", vmID).Run()
	// Delete
	cmd := exec.CommandContext(ctx, "limactl", "delete", vmID)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("limactl delete failed: %w", err)
	}
	return nil
}

func (l *LimaProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	cmd := exec.CommandContext(ctx, "limactl", "list", "--json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("limactl list failed: %w", err)
	}

	var vms []VMInfo
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var inst struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &inst); err != nil {
			continue
		}
		// Filter by dispatcher prefix
		if !strings.HasPrefix(inst.Name, "dispatcher-") {
			continue
		}
		if inst.Status == "Stopped" {
			continue
		}
		vms = append(vms, VMInfo{
			ID:    inst.Name,
			Name:  inst.Name,
			State: VMState(strings.ToLower(inst.Status)),
			Tags:  map[string]string{"dispatcher": "true"},
		})
	}
	return vms, nil
}

func (l *LimaProvider) getIP(ctx context.Context, name string) (string, error) {
	// Lima exposes SSH via limactl shell, but we need the IP for rsync.
	// Use limactl list with JSON to find the socket, or parse SSH config.
	cmd := exec.CommandContext(ctx, "limactl", "shell", name, "hostname", "-I")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("cannot get Lima VM IP: %w", err)
	}
	ips := strings.Fields(strings.TrimSpace(string(output)))
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP found for Lima VM %s", name)
	}
	return ips[0], nil
}
