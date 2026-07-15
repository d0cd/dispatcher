package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
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
	// Lima >=1.0 uses `--version`; older builds used the `version` subcommand.
	// Try modern first, fall back so we don't false-fail on legacy installs.
	if err := exec.CommandContext(ctx, "limactl", "--version").Run(); err != nil {
		if err2 := exec.CommandContext(ctx, "limactl", "version").Run(); err2 != nil {
			return fmt.Errorf("limactl not working (tried --version and version subcommand): %w", err)
		}
	}
	return nil
}

func (l *LimaProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	if opts.AllowSSHFrom != "" {
		return nil, errFirewallUnsupported("lima")
	}
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

	// Lima exposes SSH via localhost-forwarded port, NOT the VM's internal
	// IP (192.168.5.x by default — not routable from the host). Look up
	// the forwarded port so the adapter can SSH/rsync correctly.
	port, err := l.getSSHPort(ctx, opts.Name)
	if err != nil {
		_ = l.DestroyVM(ctx, opts.Name)
		return nil, fmt.Errorf("cannot get Lima SSH port: %w", err)
	}

	// Lima manages its own SSH identity (~/.lima/_config/user) and uses
	// the host's username as the VM user. Surface both through VMInfo so
	// CloudVMAdapter swaps in Lima's identity instead of generating an
	// ed25519 key the VM would never authorize.
	keyPath, err := limaIdentityPath()
	if err != nil {
		_ = l.DestroyVM(ctx, opts.Name)
		return nil, fmt.Errorf("locate Lima identity: %w", err)
	}
	sshUser := limaSSHUser()

	return &VMInfo{
		ID:         opts.Name,
		Name:       opts.Name,
		IP:         "127.0.0.1",
		SSHPort:    port,
		SSHKeyPath: keyPath,
		SSHUser:    sshUser,
		State:      VMStateRunning,
		CreatedAt:  time.Now().UTC(),
		Tags:       opts.Tags,
	}, nil
}

// limaIdentityPath returns the path to Lima's per-host SSH private key.
// Lima generates this on first use; it lives at $LIMA_HOME/_config/user
// (default $HOME/.lima/_config/user). We don't manage or delete it —
// other Lima VMs reuse the same key.
func limaIdentityPath() (string, error) {
	home := os.Getenv("LIMA_HOME")
	if home == "" {
		uhome, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		home = filepath.Join(uhome, ".lima")
	}
	path := filepath.Join(home, "_config", "user")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("no Lima identity at %s (run any `limactl start` once to bootstrap): %w", path, err)
	}
	return path, nil
}

// limaSSHUser returns the username Lima provisions inside the VM. By
// default Lima clones the host user; falls back to "lima" if we can't
// read the current user (extremely rare — would imply a broken passwd db).
func limaSSHUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	return "lima"
}

// getSSHPort returns the localhost port Lima forwards to the VM's SSH
// service. Reads `limactl list --json` and pulls `sshLocalPort`.
func (l *LimaProvider) getSSHPort(ctx context.Context, name string) (int, error) {
	out, err := exec.CommandContext(ctx, "limactl", "list", "--json", name).Output()
	if err != nil {
		return 0, fmt.Errorf("limactl list --json: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var inst struct {
			Name         string `json:"name"`
			SSHLocalPort int    `json:"sshLocalPort"`
		}
		if err := json.Unmarshal([]byte(line), &inst); err != nil {
			continue
		}
		if inst.Name == name && inst.SSHLocalPort > 0 {
			return inst.SSHLocalPort, nil
		}
	}
	return 0, fmt.Errorf("no sshLocalPort in info for Lima instance %q", name)
}

// WaitReady polls Lima's forwarded SSH port (not the VM's internal IP).
// limactl start typically returns once the VM is up + ssh-ready, so this
// is mostly defensive. ip here is "127.0.0.1" (set by CreateVM); we look
// the port up by name rather than threading it through.
func (l *LimaProvider) WaitReady(ctx context.Context, name string, _ string, _ string) error {
	port, err := l.getSSHPort(ctx, name)
	if err != nil {
		return err
	}
	return WaitForSSHOnPort(ctx, "127.0.0.1", port, 3*time.Minute)
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
