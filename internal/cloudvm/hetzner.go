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
		// cax11 is Hetzner's cheapest current server type: ARM, 2 vCPU,
		// 4 GB, ~€0.005/hr, available in EU regions. The old cx22 default
		// was removed from new accounts; cax11 is the spiritual successor.
		// Real workloads should pin a type via opts.InstanceType — picked
		// by the planner from the live pricing catalog.
		instanceType = "cax11"
	}
	if err := validateVMArgs(region, instanceType, image); err != nil {
		return nil, fmt.Errorf("hetzner: %w", err)
	}

	args := []string{
		"server", "create",
		"--name", opts.Name,
		"--type", instanceType,
		"--image", image,
		"--location", region,
		"-o", "json",
	}

	// Hetzner needs the SSH key registered in the account first, then
	// referenced by name. Upload the per-run public key under a name
	// derived from the run ID (unique across concurrent runs).
	sshKeyName := hetznerSSHKeyName(opts)
	if opts.SSHKeyPath != "" && sshKeyName != "" {
		if err := uploadHetznerSSHKey(ctx, sshKeyName, opts.SSHKeyPath); err != nil {
			return nil, err
		}
		args = append(args, "--ssh-key", sshKeyName)
	}

	// hcloud >=1.45 dropped --user-data in favor of --user-data-from-file.
	// Write to a 0600-from-creation tempfile (no TOCTOU window where the
	// umask-default mode could leak the contents) and pass the path.
	if opts.UserData != "" {
		path, err := adapter.WriteSecureTempFile("dispatcher-userdata-*.yaml", []byte(opts.UserData))
		if err != nil {
			return nil, fmt.Errorf("write user-data: %w", err)
		}
		defer os.Remove(path)
		args = append(args, "--user-data-from-file", path)
	}

	// Add labels (Hetzner's version of tags). Validated at the boundary so
	// a label value with `=` or other CLI-significant chars can't break
	// out of the --label argument.
	if err := validateLabels(opts.Tags); err != nil {
		return nil, fmt.Errorf("hetzner labels: %w", err)
	}
	for k, v := range opts.Tags {
		args = append(args, "--label", fmt.Sprintf("%s=%s", k, v))
	}

	// Per-run firewall: create it (+ inbound-SSH rule) before the server and
	// attach via --firewall, so SSH is restricted to opts.AllowSSHFrom from
	// the moment the VM boots. If we can't secure it, fail rather than create
	// an unrestricted VM.
	fwName := ""
	if opts.AllowSSHFrom != "" {
		if err := validateFirewallCIDR(opts.AllowSSHFrom); err != nil {
			return nil, err
		}
		fwName = firewallName(opts)
		if out, e := exec.CommandContext(ctx, "hcloud", hetznerFirewallCreateArgs(fwName, opts.Tags)...).CombinedOutput(); e != nil && !strings.Contains(string(out), "already") {
			return nil, fmt.Errorf("hcloud firewall create: %s: %w", string(out), e)
		}
		if out, e := exec.CommandContext(ctx, "hcloud", hetznerFirewallRuleArgs(fwName, opts.AllowSSHFrom)...).CombinedOutput(); e != nil && !strings.Contains(string(out), "already") {
			_ = exec.CommandContext(context.Background(), "hcloud", "firewall", "delete", fwName).Run()
			return nil, fmt.Errorf("hcloud firewall add-rule: %s: %w", string(out), e)
		}
		args = append(args, "--firewall", fwName)
	}

	output, err := retryCLIOutput(ctx, "hcloud", "hcloud server create", args...)
	if err != nil {
		// VM creation failed but we may have already uploaded the SSH key and
		// created the firewall. Best-effort cleanup so we don't leak them.
		if sshKeyName != "" {
			_ = exec.CommandContext(context.Background(), "hcloud", "ssh-key", "delete", sshKeyName).Run()
		}
		if fwName != "" {
			_ = exec.CommandContext(context.Background(), "hcloud", "firewall", "delete", fwName).Run()
		}
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
	output, err := runCLI(ctx, "hcloud", "server", "describe", vmID, "-o", "json")
	if err != nil {
		if isVMNotFound(err, vmID) {
			return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
		}
		return nil, wrapExecError("hcloud server describe", err)
	}

	var server struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Status    string `json:"status"`
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
	// Recover the run id from the server's labels BEFORE deletion so we can
	// delete the per-run firewall afterward (it can't be deleted while still
	// attached to the server).
	runID := h.runIDForServer(ctx, vmID)

	if _, err := runCLI(ctx, "hcloud", "server", "delete", vmID); err != nil {
		return fmt.Errorf("hcloud server delete failed: %w", err)
	}
	if runID != "" {
		// Best-effort: the firewall only exists when --allow-ssh-from was set.
		_, _ = runCLI(ctx, "hcloud", "firewall", "delete", firewallNameFromString(runID))
		// Delete the per-run SSH key using the run id recovered BEFORE deletion —
		// re-describing the now-deleted server would fail and leak the key.
		_, _ = runCLI(ctx, "hcloud", "ssh-key", "delete", "dispatcher-"+runID)
	}
	return nil
}

// runIDForServer reads the dispatcher-run-id label off a server before it is
// deleted. Best-effort: returns "" if the server is already gone.
func (h *HetznerProvider) runIDForServer(ctx context.Context, vmID string) string {
	out, err := runCLI(ctx, "hcloud", "server", "describe", vmID, "-o", "json")
	if err != nil {
		return ""
	}
	var srv struct {
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &srv); err != nil {
		return ""
	}
	return srv.Labels["dispatcher-run-id"]
}

// hetznerSSHKeyName derives a stable per-run name for the SSH key dispatcher
// uploads to Hetzner. Hetzner requires SSH keys to be account-registered
// before they can be injected into a VM at create time. We delete them
// during VM teardown so they don't accumulate.
func hetznerSSHKeyName(opts VMOptions) string {
	runID := opts.Tags["dispatcher-run-id"]
	if runID == "" {
		// Fall back to VM name if no run id is in tags (legacy callers).
		return "dispatcher-" + opts.Name
	}
	return "dispatcher-" + runID
}

// uploadHetznerSSHKey registers a public key with the Hetzner account
// under `name`. Tolerates "already exists" since concurrent retries can
// race the upload.
func uploadHetznerSSHKey(ctx context.Context, name, pubKeyPath string) error {
	out, err := exec.CommandContext(ctx, "hcloud", "ssh-key", "create",
		"--name", name,
		"--public-key-from-file", pubKeyPath,
	).CombinedOutput()
	if err != nil {
		// "already exists" is fine — concurrent uploads, retries, etc.
		if strings.Contains(string(out), "already_exists") ||
			strings.Contains(string(out), "already exists") {
			return nil
		}
		return fmt.Errorf("hcloud ssh-key create: %s: %w", string(out), err)
	}
	return nil
}

// cleanupHetznerSSHKeysForVM removes the dispatcher-uploaded SSH key
// associated with a VM. The key is named "dispatcher-<run-id>"; we find
// the right one by listing keys with the dispatcher label and matching
// against the VM's run-id label.
//

func (h *HetznerProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	if err := validateLabels(tags); err != nil {
		return nil, fmt.Errorf("hetzner selector: %w", err)
	}
	args := []string{"server", "list", "-o", "json"}
	for k, v := range tags {
		args = append(args, "--selector", fmt.Sprintf("%s=%s", k, v))
	}

	output, err := runCLI(ctx, "hcloud", args...)
	if err != nil {
		return nil, fmt.Errorf("hcloud server list failed: %w", err)
	}

	var servers []struct {
		ID      int               `json:"id"`
		Name    string            `json:"name"`
		Status  string            `json:"status"`
		Labels  map[string]string `json:"labels"`
		Created string            `json:"created"`
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
