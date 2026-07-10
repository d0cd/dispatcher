package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// gcpConfidentialSpaceCreateArgs builds the `gcloud compute instances create`
// argv for a Confidential Space container VM that launches
// opts.ConfidentialSpaceImage as its measured workload. The recipe is
// live-validated (docs/confidential-space-execution.md): SEV + secure boot, the
// confidential-space image, tee-* metadata, and — crucially — `--scopes=
// cloud-platform`, without which the container-launcher's verifier client fails
// ("insufficient authentication scopes") and the workload never runs. There is
// no ssh-keys/startup-script: the workload is the container, reached over its own
// TCP endpoint, not SSH.
func gcpConfidentialSpaceCreateArgs(opts VMOptions, zone, project string) []string {
	machineType := opts.InstanceType
	if machineType == "" {
		machineType = "n2d-standard-2" // AMD SEV-capable default
	}
	args := []string{
		"compute", "instances", "create", opts.Name,
		"--zone", zone,
		"--machine-type", machineType,
		"--confidential-compute-type=SEV",
		"--shielded-secure-boot",
		"--maintenance-policy=TERMINATE",
		"--scopes=cloud-platform",
		"--image-family=confidential-space",
		"--image-project=confidential-space-images",
		"--metadata", strings.Join([]string{
			"tee-image-reference=" + opts.ConfidentialSpaceImage,
			"tee-container-log-redirect=true",
			"tee-restart-policy=Never",
		}, ","),
		"--format", "json",
		"--quiet",
	}
	// A network tag ties the VM to its per-run agent-port firewall.
	if opts.ConfidentialAllowFrom != "" {
		args = append(args, "--tags="+agentFirewallName(opts.Name))
	}
	if len(opts.Tags) > 0 {
		keys := make([]string, 0, len(opts.Tags))
		for k := range opts.Tags {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic argv
		pairs := make([]string, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, k+"="+opts.Tags[k])
		}
		args = append(args, "--labels", strings.Join(pairs, ","))
	}
	if project != "" {
		args = append(args, "--project", project)
	}
	return args
}

// agentFirewallName is the deterministic name of a run's agent-port firewall
// rule (also used as the VM's network tag), so create and cleanup agree without
// threading extra state.
func agentFirewallName(vmName string) string {
	return firewallNameFromString("cs-" + vmName)
}

// gcpAgentFirewallCreateArgs opens the agent port (8443) to cidr for VMs carrying
// targetTag. The endpoint is safe to expose (sealing + attestation), so this is
// defense-in-depth, not the security boundary.
func gcpAgentFirewallCreateArgs(name, targetTag, cidr, project string) []string {
	args := []string{
		"compute", "firewall-rules", "create", name,
		fmt.Sprintf("--allow=tcp:%d", csAgentPort),
		"--source-ranges=" + cidr,
		"--target-tags=" + targetTag,
		"--quiet",
	}
	if project != "" {
		args = append(args, "--project", project)
	}
	return args
}

func gcpAgentFirewallDeleteArgs(name, project string) []string {
	args := []string{"compute", "firewall-rules", "delete", name, "--quiet"}
	if project != "" {
		args = append(args, "--project", project)
	}
	return args
}

// createAgentFirewall / deleteAgentFirewall let the Confidential Space adapter
// manage the agent-port rule's lifecycle alongside the VM (agentFirewaller).
func (g *GCPProvider) createAgentFirewall(ctx context.Context, name, cidr string) error {
	if err := validateFirewallCIDR(cidr); err != nil {
		return err
	}
	_, err := runCLI(ctx, "gcloud", gcpAgentFirewallCreateArgs(name, name, cidr, g.project)...)
	return err
}

func (g *GCPProvider) deleteAgentFirewall(ctx context.Context, name string) error {
	_, err := runCLI(ctx, "gcloud", gcpAgentFirewallDeleteArgs(name, g.project)...)
	return err
}

// createConfidentialSpaceVM provisions a GCP Confidential Space VM. The agent's
// TCP endpoint still needs a firewall rule opening its port to dispatcher's
// egress IP — the adapter owns that so the rule's lifecycle matches the run.
func (g *GCPProvider) createConfidentialSpaceVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	zone := opts.Region
	if zone == "" {
		zone = g.zone
	}
	if err := validateLabels(opts.Tags); err != nil {
		return nil, fmt.Errorf("gcp labels: %w", err)
	}
	if opts.ConfidentialAllowFrom != "" {
		if err := validateFirewallCIDR(opts.ConfidentialAllowFrom); err != nil {
			return nil, err
		}
	}
	args := gcpConfidentialSpaceCreateArgs(opts, zone, g.project)

	output, err := retryCLIOutput(ctx, "gcloud", "gcloud compute instances create", args...)
	if err != nil {
		return nil, err
	}

	// Open the agent port to dispatcher's egress IP. A VM the caller can't reach
	// is useless, so on failure reap the VM before returning (CreateVM's error
	// contract leaves no handle for the caller to clean up).
	if opts.ConfidentialAllowFrom != "" {
		if err := g.createAgentFirewall(ctx, agentFirewallName(opts.Name), opts.ConfidentialAllowFrom); err != nil {
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = g.DestroyVM(cctx, opts.Name)
			return nil, fmt.Errorf("open agent-port firewall: %w", err)
		}
	}

	var instances []struct {
		NetworkInterfaces []struct {
			AccessConfigs []struct {
				NatIP string `json:"natIP"`
			} `json:"accessConfigs"`
		} `json:"networkInterfaces"`
	}
	if err := json.Unmarshal(output, &instances); err != nil {
		return nil, fmt.Errorf("cannot parse gcloud output: %w", err)
	}
	if len(instances) == 0 {
		return nil, fmt.Errorf("no instances created")
	}
	ip := ""
	if len(instances[0].NetworkInterfaces) > 0 && len(instances[0].NetworkInterfaces[0].AccessConfigs) > 0 {
		ip = instances[0].NetworkInterfaces[0].AccessConfigs[0].NatIP
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
