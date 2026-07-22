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

// SetRegion re-points the default zone (GCP uses the region field as a zone).
func (g *GCPProvider) SetRegion(region string) {
	if region != "" {
		g.zone = region
	}
}

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
	// Confidential Space is a distinct provisioning mode: the workload is a
	// measured container launched via tee-image-reference, not an SSH VM.
	if opts.ConfidentialSpaceImage != "" {
		return g.createConfidentialSpaceVM(ctx, opts)
	}

	zone := opts.Region
	if zone == "" {
		zone = g.zone
	}
	instanceType := opts.InstanceType
	if instanceType == "" {
		instanceType = "e2-medium"
		if opts.ConfidentialType != "" {
			// e2 rejects --confidential-compute-type/--min-cpu-platform. n2d
			// covers SEV/SEV-SNP; TDX needs an Intel c3.
			instanceType = "n2d-standard-2"
			if gcpConfidentialComputeType(opts.ConfidentialType) == "TDX" {
				instanceType = "c3-standard-4"
			}
		}
	}
	image := opts.Image
	customImage := false
	if image == "" {
		// Ubuntu 24.04 publishes arch-suffixed families; the bare
		// "ubuntu-2404-lts" is not a resolvable family in ubuntu-os-cloud.
		image = "ubuntu-2404-lts-amd64"
		if gcpIsGPUMachine(instanceType) && gcpGPUImage() != "" {
			// GPU VMs need the NVIDIA driver preinstalled; the operator supplies
			// a driver-baked image (in the current project).
			image = gcpGPUImage()
			customImage = true
		}
	}
	if err := validateVMArgs(zone, instanceType, image); err != nil {
		return nil, fmt.Errorf("gcp: %w", err)
	}

	args := []string{
		"compute", "instances", "create", opts.Name,
		"--zone", zone,
		"--machine-type", instanceType,
		"--format", "json",
		"--quiet",
	}
	if customImage {
		args = append(args, "--image", image) // resolves in the current project
	} else {
		args = append(args, "--image-family", image, "--image-project", "ubuntu-os-cloud")
	}

	args = append(args, gcpConfidentialArgs(opts)...)

	// GPU VMs and SPOT instances can't live-migrate, so GCP requires TERMINATE on
	// host maintenance or rejects the create. Confidential already sets it (above);
	// apply it here for GPU families or spot when it hasn't been set.
	if opts.ConfidentialType == "" && (gcpIsGPUMachine(instanceType) || opts.Spot) {
		args = append(args, "--maintenance-policy=TERMINATE")
	}

	// Spot: interruptible provisioning at the spot price. The VM is deleted (not
	// stopped) on preemption, so an ephemeral run leaves nothing behind.
	if opts.Spot {
		args = append(args, "--provisioning-model=SPOT", "--instance-termination-action=DELETE")
	}

	if g.project != "" {
		args = append(args, "--project", g.project)
	}
	// --metadata k=<blob> would let any byte in a value (newline, =, --) corrupt
	// or inject gcloud args. --metadata-from-file keeps blobs entirely off argv
	// and out of process listings. Multiple entries are comma-joined into one
	// flag (a repeated --metadata-from-file would otherwise clobber the prior).
	var metadataFiles []string
	if opts.UserData != "" {
		path, err := adapter.WriteSecureTempFile("dispatcher-gcp-userdata-*.sh", []byte(opts.UserData))
		if err != nil {
			return nil, fmt.Errorf("write user-data: %w", err)
		}
		defer os.Remove(path)
		metadataFiles = append(metadataFiles, "startup-script="+path)
	}
	if opts.SSHKeyPath != "" && opts.SSHUser != "" {
		pub, err := os.ReadFile(opts.SSHKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read ssh pubkey: %w", err)
		}
		keysPath, err := adapter.WriteSecureTempFile("dispatcher-gcp-sshkeys-*.txt",
			[]byte(gcpSSHKeysValue(opts.SSHUser, string(pub))))
		if err != nil {
			return nil, fmt.Errorf("write ssh-keys metadata: %w", err)
		}
		defer os.Remove(keysPath)
		metadataFiles = append(metadataFiles, "ssh-keys="+keysPath)
	}
	if len(metadataFiles) > 0 {
		args = append(args, "--metadata-from-file", strings.Join(metadataFiles, ","))
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
		// A transient error after the instance was created would otherwise leak a
		// billing VM; adopt it if the retry-then-"already exists" left one behind.
		if vm := adoptCreatedVM(ctx, g, opts.Tags["dispatcher-run-id"]); vm != nil {
			return vm, nil
		}
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
	var out []byte
	err := Retry(ctx, DefaultRetry, IsTransient, func() error {
		var runErr error
		out, runErr = runCLI(ctx, "gcloud", args...)
		return runErr
	})
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

// gcpGPUImage is the operator-provided driver-baked image for GPU VMs (in the
// current project). Empty = fall back to stock Ubuntu (no driver).
func gcpGPUImage() string { return os.Getenv("DISPATCHER_GCP_GPU_IMAGE") }

// gcpIsGPUMachine reports whether instanceType is a GCP machine family that
// carries attached GPUs (a2/a3 = A100/H100, g2 = L4), which mandates a
// TERMINATE maintenance policy.
func gcpIsGPUMachine(instanceType string) bool {
	for _, prefix := range []string{"a2-", "a3-", "g2-"} {
		if strings.HasPrefix(instanceType, prefix) {
			return true
		}
	}
	return false
}

// gcpSSHKeysValue formats a public key for GCP's ssh-keys metadata, which binds
// the key to a login user as "<user>:<pubkey>". The guest agent then creates the
// user (if needed) and installs the key. The trailing newline from a .pub file
// is stripped so the metadata value is a single clean line.
func gcpSSHKeysValue(user, pubKey string) string {
	return user + ":" + strings.TrimSpace(pubKey)
}

// gcpConfidentialArgs returns the GCP create flags for a confidential VM (or
// nil for a non-confidential one). Confidential VMs can't live-migrate, so
// maintenance must TERMINATE. The catalog picks a compatible machine type
// (n2d for SEV/SEV-SNP, c3 for TDX); if it doesn't, gcloud errors honestly.
func gcpConfidentialArgs(opts VMOptions) []string {
	if opts.ConfidentialType == "" {
		return nil
	}
	ccType := gcpConfidentialComputeType(opts.ConfidentialType)
	args := []string{
		"--confidential-compute-type=" + ccType,
		"--maintenance-policy=TERMINATE",
	}
	if ccType == "SEV_SNP" {
		// SEV-SNP needs AMD Milan or newer. Without pinning the CPU platform an
		// N2D instance can schedule onto AMD Rome, which supports only SEV — the
		// VM would boot but never produce an SNP attestation report.
		args = append(args, "--min-cpu-platform", "AMD Milan")
	}
	return args
}

// gcpConfidentialComputeType maps a dispatcher TEE type to GCP's
// --confidential-compute-type value. "any" and "sev-snp" both pick SEV_SNP
// (AMD's strongest); SEV and TDX map through.
func gcpConfidentialComputeType(t string) string {
	switch t {
	case "sev":
		return "SEV"
	case "tdx":
		return "TDX"
	default: // "sev-snp", "any"
		return "SEV_SNP"
	}
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
		if isVMNotFound(err, vmID) {
			return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
		}
		return nil, wrapExecError("gcloud compute instances describe", err)
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
		// Already gone — teardown is idempotent (matches OCI + the GetVM contract),
		// so a retried/racing gc pass doesn't report a spurious cleanup failure.
		if isVMNotFound(err, vmID) {
			return nil
		}
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
