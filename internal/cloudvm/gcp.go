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

// GCPProvider implements Provider using the gcloud CLI.
type GCPProvider struct {
	project string
	zone    string
}

// NewGCPProvider creates a GCP provider.
func NewGCPProvider(project, zone string) *GCPProvider {
	if zone == "" {
		zone = "us-central1-a"
	}
	return &GCPProvider{project: project, zone: zone}
}

func (g *GCPProvider) Name() ProviderID { return ProviderGCP }

func (g *GCPProvider) CheckCLI(ctx context.Context) error {
	if _, err := exec.LookPath("gcloud"); err != nil {
		return fmt.Errorf("gcloud CLI not found: %w", err)
	}
	cmd := exec.CommandContext(ctx, "gcloud", "auth", "print-access-token")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gcloud not authenticated: %w", err)
	}
	return nil
}

func (g *GCPProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	zone := opts.Region
	if zone == "" {
		zone = g.zone
	}
	instanceType := opts.InstanceType
	if instanceType == "" {
		instanceType = "e2-medium"
	}
	image := opts.Image
	if image == "" {
		image = "ubuntu-2404-lts"
	}
	if err := validateVMArgs(zone, instanceType, image); err != nil {
		return nil, fmt.Errorf("gcp: %w", err)
	}

	args := []string{
		"compute", "instances", "create", opts.Name,
		"--zone", zone,
		"--machine-type", instanceType,
		"--image-family", image,
		"--image-project", "ubuntu-os-cloud",
		"--format", "json",
		"--quiet",
	}

	if g.project != "" {
		args = append(args, "--project", g.project)
	}
	if opts.UserData != "" {
		// --metadata startup-script=<blob> would let any byte in UserData
		// (newline, =, --) corrupt or inject gcloud args. --metadata-from-file
		// keeps the blob entirely off argv and out of process listings.
		path, err := adapter.WriteSecureTempFile("dispatcher-gcp-userdata-*.sh", []byte(opts.UserData))
		if err != nil {
			return nil, fmt.Errorf("write user-data: %w", err)
		}
		defer os.Remove(path)
		args = append(args, "--metadata-from-file", "startup-script="+path)
	}

	// GCP labels: validated at the boundary so a key/value with a comma or
	// space can't break out of the comma-joined --labels argument.
	if err := validateLabels(opts.Tags); err != nil {
		return nil, fmt.Errorf("gcp labels: %w", err)
	}
	if len(opts.Tags) > 0 {
		pairs := make([]string, 0, len(opts.Tags))
		for k, v := range opts.Tags {
			pairs = append(pairs, k+"="+v)
		}
		args = append(args, "--labels", strings.Join(pairs, ","))
	}

	// A per-run firewall is not yet implementable correctly on GCP: instances
	// land on the project's default network, whose built-in default-allow-ssh
	// rule permits tcp:22 from 0.0.0.0/0, and an additive ALLOW rule cannot
	// subtract that access. Rejecting (rather than attaching a no-op rule that
	// implies SSH is locked down) avoids false confidence.
	if opts.AllowSSHFrom != "" {
		return nil, errFirewallUnsupported("gcp")
	}

	output, err := retryCLIOutput(ctx, "gcloud", "gcloud compute instances create", args...)
	if err != nil {
		return nil, err
	}

	var instances []struct {
		Name              string `json:"name"`
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
		ID:        opts.Name, // GCP uses name as ID
		Name:      opts.Name,
		IP:        ip,
		State:     VMStateRunning,
		CreatedAt: time.Now().UTC(),
		Tags:      opts.Tags,
	}, nil
}

func (g *GCPProvider) WaitReady(ctx context.Context, _ string, ip string, _ string) error {
	return WaitForSSH(ctx, ip, 5*time.Minute)
}

// resolveZone discovers the actual zone of an instance by name so GetVM and
// DestroyVM act on a VM created in a non-default zone instead of assuming
// g.zone (which would false-terminate its status and leak it on teardown).
// Falls back to g.zone when discovery fails or the instance isn't found.
func (g *GCPProvider) resolveZone(ctx context.Context, vmID string) string {
	args := []string{
		"compute", "instances", "list",
		"--filter", "name=" + vmID,
		"--format", "value(zone)",
	}
	if g.project != "" {
		args = append(args, "--project", g.project)
	}
	out, err := runCLI(ctx, "gcloud", args...)
	if err != nil {
		return g.zone
	}
	zone := strings.TrimSpace(string(out))
	if i := strings.IndexByte(zone, '\n'); i >= 0 {
		zone = zone[:i] // first match if a name somehow exists in two zones
	}
	// value(zone) may render as a full resource URL; keep the trailing segment.
	if i := strings.LastIndexByte(zone, '/'); i >= 0 {
		zone = zone[i+1:]
	}
	if zone == "" {
		return g.zone
	}
	return zone
}

func (g *GCPProvider) GetVM(ctx context.Context, vmID string) (*VMInfo, error) {
	args := []string{
		"compute", "instances", "describe", vmID,
		"--zone", g.resolveZone(ctx, vmID),
		"--format", "json",
	}
	if g.project != "" {
		args = append(args, "--project", g.project)
	}

	output, err := runCLI(ctx, "gcloud", args...)
	if err != nil {
		return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
	}

	var inst struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(output, &inst); err != nil {
		return nil, err
	}

	state := VMStateRunning
	if inst.Status == "TERMINATED" || inst.Status == "STOPPING" {
		state = VMStateTerminated
	}

	return &VMInfo{ID: vmID, Name: inst.Name, State: state}, nil
}

func (g *GCPProvider) DestroyVM(ctx context.Context, vmID string) error {
	args := []string{
		"compute", "instances", "delete", vmID,
		"--zone", g.resolveZone(ctx, vmID),
		"--quiet",
	}
	if g.project != "" {
		args = append(args, "--project", g.project)
	}
	if _, err := runCLI(ctx, "gcloud", args...); err != nil {
		return fmt.Errorf("gcloud compute instances delete failed: %w", err)
	}
	return nil
}

func (g *GCPProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	args := []string{"compute", "instances", "list", "--format", "json"}
	if g.project != "" {
		args = append(args, "--project", g.project)
	}

	// GCP filter syntax for labels. Validate first — `AND`, parens, and
	// quotes are reserved in the gcloud filter language; a label value
	// containing them would corrupt the predicate.
	if err := validateLabels(tags); err != nil {
		return nil, fmt.Errorf("gcp filter labels: %w", err)
	}
	var filters []string
	for k, v := range tags {
		filters = append(filters, fmt.Sprintf("labels.%s=%s", k, v))
	}
	if len(filters) > 0 {
		args = append(args, "--filter", strings.Join(filters, " AND "))
	}

	output, err := runCLI(ctx, "gcloud", args...)
	if err != nil {
		return nil, wrapExecError("gcloud compute instances list", err)
	}

	var instances []struct {
		Name   string            `json:"name"`
		Status string            `json:"status"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(output, &instances); err != nil {
		return nil, err
	}

	var vms []VMInfo
	for _, inst := range instances {
		if inst.Status == "TERMINATED" {
			continue
		}
		vms = append(vms, VMInfo{
			ID:    inst.Name,
			Name:  inst.Name,
			State: VMState(inst.Status),
			Tags:  inst.Labels,
		})
	}
	return vms, nil
}
