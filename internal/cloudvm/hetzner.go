package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// HetznerProvider implements Provider using the hcloud CLI.
type HetznerProvider struct {
	defaultRegion string
	defaultImage  string
}

// NewHetznerProvider creates a Hetzner provider.
func NewHetznerProvider(region string) *HetznerProvider {
	if region == "" {
		region = "fsn1"
	}
	return &HetznerProvider{
		defaultRegion: region,
		defaultImage:  "ubuntu-24.04",
	}
}

func (h *HetznerProvider) Name() ProviderID { return ProviderHetzner }

func (h *HetznerProvider) CheckCLI(ctx context.Context) error {
	if _, err := exec.LookPath("hcloud"); err != nil {
		return fmt.Errorf("hcloud CLI not found: %w", err)
	}
	// Check authentication
	cmd := exec.CommandContext(ctx, "hcloud", "server", "list", "-o", "json")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("hcloud not authenticated: %w", err)
	}
	return nil
}

func (h *HetznerProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	region := opts.Region
	if region == "" {
		region = h.defaultRegion
	}
	image := opts.Image
	if image == "" {
		image = h.defaultImage
	}
	instanceType := opts.InstanceType
	if instanceType == "" {
		instanceType = "cx22"
	}

	args := []string{
		"server", "create",
		"--name", opts.Name,
		"--type", instanceType,
		"--image", image,
		"--location", region,
		"-o", "json",
	}

	if opts.SSHKeyPath != "" {
		args = append(args, "--ssh-key", opts.SSHKeyPath)
	}
	if opts.UserData != "" {
		args = append(args, "--user-data", opts.UserData)
	}

	// Add labels (Hetzner's version of tags)
	for k, v := range opts.Tags {
		args = append(args, "--label", fmt.Sprintf("%s=%s", k, v))
	}

	var output []byte
	err := Retry(ctx, DefaultRetry, IsTransient, func() error {
		var runErr error
		output, runErr = exec.CommandContext(ctx, "hcloud", args...).Output()
		if runErr != nil {
			return wrapExecError("hcloud server create", runErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var result struct {
		Server struct {
			ID        int    `json:"id"`
			Name      string `json:"name"`
			PublicNet struct {
				IPv4 struct {
					IP string `json:"ip"`
				} `json:"ipv4"`
			} `json:"public_net"`
		} `json:"server"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("cannot parse hcloud output: %w", err)
	}

	return &VMInfo{
		ID:        fmt.Sprintf("%d", result.Server.ID),
		Name:      result.Server.Name,
		IP:        result.Server.PublicNet.IPv4.IP,
		State:     VMStateRunning,
		CreatedAt: time.Now().UTC(),
		Tags:      opts.Tags,
	}, nil
}

func (h *HetznerProvider) WaitReady(ctx context.Context, _ string, ip string, _ string) error {
	return WaitForSSH(ctx, ip, 5*time.Minute)
}

func (h *HetznerProvider) GetVM(ctx context.Context, vmID string) (*VMInfo, error) {
	cmd := exec.CommandContext(ctx, "hcloud", "server", "describe", vmID, "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("hcloud server describe failed: %w", err)
	}

	var server struct {
		ID     int    `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
		PublicNet struct {
			IPv4 struct {
				IP string `json:"ip"`
			} `json:"ipv4"`
		} `json:"public_net"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(output, &server); err != nil {
		return nil, fmt.Errorf("cannot parse hcloud output: %w", err)
	}

	state := VMStateRunning
	switch server.Status {
	case "running":
		state = VMStateRunning
	case "off", "stopping":
		state = VMStateStopping
	case "deleting":
		state = VMStateTerminated
	}

	return &VMInfo{
		ID:    fmt.Sprintf("%d", server.ID),
		Name:  server.Name,
		IP:    server.PublicNet.IPv4.IP,
		State: state,
		Tags:  server.Labels,
	}, nil
}

func (h *HetznerProvider) DestroyVM(ctx context.Context, vmID string) error {
	cmd := exec.CommandContext(ctx, "hcloud", "server", "delete", vmID)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("hcloud server delete failed: %w", err)
	}
	return nil
}

func (h *HetznerProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	args := []string{"server", "list", "-o", "json"}
	for k, v := range tags {
		args = append(args, "--selector", fmt.Sprintf("%s=%s", k, v))
	}

	cmd := exec.CommandContext(ctx, "hcloud", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("hcloud server list failed: %w", err)
	}

	var servers []struct {
		ID     int               `json:"id"`
		Name   string            `json:"name"`
		Status string            `json:"status"`
		Labels map[string]string `json:"labels"`
		Created string           `json:"created"`
	}
	if err := json.Unmarshal(output, &servers); err != nil {
		return nil, fmt.Errorf("cannot parse hcloud output: %w", err)
	}

	var vms []VMInfo
	for _, s := range servers {
		created, _ := time.Parse(time.RFC3339, s.Created)
		vms = append(vms, VMInfo{
			ID:        fmt.Sprintf("%d", s.ID),
			Name:      s.Name,
			State:     VMState(strings.ToLower(s.Status)),
			CreatedAt: created,
			Tags:      s.Labels,
		})
	}
	return vms, nil
}
