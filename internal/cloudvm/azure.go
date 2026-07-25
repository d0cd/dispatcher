package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/dlog"
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
		if err := validateFirewallCIDR(opts.AllowSSHFrom); err != nil {
			return nil, fmt.Errorf("azure: %w", err)
		}
	}

	args := []string{
		"vm", "create",
		"--resource-group", a.resourceGroup,
		"--name", opts.Name,
		"--location", location,
		"--size", instanceType,
		"--image", image,
		"--admin-username", "dispatcher",
		// System-assigned managed identity so the guest watchdog can deallocate
		// itself at TTL (a bare halt leaves an Azure VM Stopped-allocated, still
		// compute-billing). Deallocate rights are granted below, scoped to the VM.
		"--assign-identity", "[system]",
		"--output", "json",
	}
	// Per-run SSH firewall: create the VM with NO default SSH rule (Azure
	// default-denies inbound from the Internet), then add one scoped ALLOW rule
	// below — SSH is reachable only from opts.AllowSSHFrom, never briefly open.
	if opts.AllowSSHFrom != "" {
		args = append(args, "--nsg-rule", "NONE")
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

	// Spot: interruptible Spot priority. --max-price -1 caps at the on-demand
	// price (evicted on capacity, never on price); --eviction-policy Delete leaves
	// nothing behind when reclaimed.
	if opts.Spot {
		args = append(args, "--priority", "Spot", "--eviction-policy", "Delete", "--max-price", "-1")
	}

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
		// A transient error after the VM was created would otherwise leak it; adopt
		// it if the retry-then-"already exists" left one behind.
		if vm := adoptCreatedVM(ctx, a, opts.Tags["dispatcher-run-id"]); vm != nil {
			return vm, nil
		}
		// az masks a NotAvailableForSubscription error as a "content already
		// consumed" CLI crash. Only in that case, probe the SKU: if it's
		// unavailable for this subscription (an offer/region restriction, not a
		// quota), substitute the smallest available general-purpose size and
		// retry the create once rather than failing the run outright.
		if strings.Contains(err.Error(), "already consumed") {
			if ok, reason := azureSKUAvailable(ctx, location, instanceType); !ok {
				// Only substitute a general-purpose size for another one. A GPU
				// (N-series) or confidential (DC/EC, or any confidential run) request
				// can't be preserved by a general-purpose substitute, so fail closed
				// with the actionable reason rather than silently downgrading the
				// workload onto a CPU-only / non-confidential VM.
				if opts.ConfidentialType != "" || !azureGeneralPurpose(instanceType) {
					return nil, fmt.Errorf("azure: VM size %s is %s in %s — choose a different --size or region: %w",
						instanceType, reason, location, err)
				}
				alt, altErr := firstAvailableAzureSKU(ctx, location, instanceType)
				if altErr != nil {
					return nil, fmt.Errorf("azure: VM size %s is %s in %s and no available substitute was found (%v): %w",
						instanceType, reason, location, altErr, err)
				}
				dlog.L().Warn("azure.sku.substituted",
					"requested", instanceType, "using", alt, "location", location, "reason", reason)
				output, err = retryCLIOutput(ctx, "az", "az vm create", withAzureSize(args, alt)...)
				if err != nil {
					if vm := adoptCreatedVM(ctx, a, opts.Tags["dispatcher-run-id"]); vm != nil {
						return vm, nil
					}
					return nil, fmt.Errorf("azure: substitute size %s for unavailable %s also failed: %w", alt, instanceType, err)
				}
				instanceType = alt // the VM that actually launched, for the run state
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	var result struct {
		ID              string `json:"id"`
		PublicIpAddress string `json:"publicIpAddress"`
		Identity        struct {
			PrincipalId string `json:"principalId"`
		} `json:"identity"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("cannot parse az output: %w", err)
	}

	// Scope SSH to the requested CIDR on the auto-created <name>NSG. On failure,
	// reap the VM rather than leave one whose SSH posture is undefined.
	if opts.AllowSSHFrom != "" {
		if err := a.createSSHRule(ctx, opts.Name, opts.AllowSSHFrom); err != nil {
			cctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			_ = a.DestroyVM(cctx, opts.Name)
			return nil, fmt.Errorf("azure ssh firewall: %w", err)
		}
	}

	// Let the VM's identity deallocate itself at watchdog TTL. Best-effort: an
	// operator without role-assignment rights keeps the gc backstop.
	if result.Identity.PrincipalId != "" && result.ID != "" {
		a.grantSelfDeallocate(ctx, result.Identity.PrincipalId, result.ID)
	}

	return &VMInfo{
		ID:           opts.Name, // Azure uses name for most operations
		Name:         opts.Name,
		IP:           result.PublicIpAddress,
		State:        VMStateRunning,
		InstanceType: instanceType, // the size actually launched (may be a substitute)
		CreatedAt:    time.Now().UTC(),
		Tags:         opts.Tags,
	}, nil
}

// createSSHRule adds a least-privilege inbound SSH rule (tcp/22 from cidr) to the
// VM's auto-created <name>NSG. The VM is created with --nsg-rule NONE, so this is
// the only inbound allow and SSH is reachable only from cidr. If the NSG isn't
// present the rule-create fails loud (never leaving SSH silently open).
func (a *AzureProvider) createSSHRule(ctx context.Context, vmName, cidr string) error {
	_, err := runCLI(ctx, "az", "network", "nsg", "rule", "create",
		"--resource-group", a.resourceGroup,
		"--nsg-name", vmName+"NSG",
		"--name", "dispatcher-ssh",
		"--priority", "300",
		"--destination-port-ranges", sshPort,
		"--source-address-prefixes", cidr,
		"--access", "Allow", "--protocol", "Tcp", "--direction", "Inbound")
	return err
}

// grantSelfDeallocate grants the VM's system-assigned identity permission to
// deallocate itself, scoped to the VM resource (least privilege — the identity
// can manage only its own VM). "Virtual Machine Contributor" is the built-in role
// carrying Microsoft.Compute/virtualMachines/deallocate/action. Best-effort: an
// operator without Microsoft.Authorization/roleAssignments/write keeps the
// existing gc backstop, so a failure is logged, not fatal.
func (a *AzureProvider) grantSelfDeallocate(ctx context.Context, principalID, vmResourceID string) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := runCLI(cctx, "az", "role", "assignment", "create",
		"--assignee-object-id", principalID,
		"--assignee-principal-type", "ServicePrincipal",
		"--role", "Virtual Machine Contributor",
		"--scope", vmResourceID,
		"--output", "none",
	); err != nil {
		dlog.L().Warn("azure.self_deallocate.role_assignment_failed",
			"err", err.Error(),
			"hint", "guest watchdog will halt (Stopped-allocated); dispatcher gc reclaims it")
	}
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

// azureListedSKU is one entry of `az vm list-skus` output.
type azureListedSKU struct {
	Name         string `json:"name"`
	Capabilities []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"capabilities"`
	Restrictions []struct {
		ReasonCode string `json:"reasonCode"`
	} `json:"restrictions"`
}

func (s azureListedSKU) capability(key string) string {
	for _, c := range s.Capabilities {
		if c.Name == key {
			return c.Value
		}
	}
	return ""
}

func (s azureListedSKU) available() bool {
	for _, r := range s.Restrictions {
		if r.ReasonCode != "" {
			return false
		}
	}
	return true
}

// azureGeneralPurpose reports whether a VM size is in a general-purpose or
// compute family (A/B/D/E/F), excluding GPU (N), HPC (H), large-memory (M),
// storage (L), and confidential (DC/EC) families — those carry special images,
// cost, or quota that make them poor automatic substitutes.
func azureGeneralPurpose(name string) bool {
	fam := strings.TrimPrefix(name, "Standard_")
	i := 0
	for i < len(fam) && (fam[i] < '0' || fam[i] > '9') {
		i++
	}
	prefix := fam[:i]
	if prefix == "" || strings.HasPrefix(prefix, "DC") || strings.HasPrefix(prefix, "EC") {
		return false
	}
	switch prefix[0] {
	case 'A', 'B', 'D', 'E', 'F':
		return true
	}
	return false
}

// firstAvailableAzureSKU finds an available general-purpose VM size in the
// location that meets or exceeds the requested size's vCPU/memory. It is the
// substitute used when the requested size is NotAvailableForSubscription — a
// region/offer restriction (not a quota) that `az vm create` masks as a crash.
func firstAvailableAzureSKU(ctx context.Context, location, requested string) (string, error) {
	out, err := runCLI(ctx, "az", "vm", "list-skus",
		"--location", location, "--resource-type", "virtualMachines", "--all", "--output", "json")
	if err != nil {
		return "", err
	}
	var skus []azureListedSKU
	if err := json.Unmarshal(out, &skus); err != nil {
		return "", fmt.Errorf("parse az vm list-skus: %w", err)
	}

	minVCPU, minMem := 1, 0.0
	for _, s := range skus {
		if s.Name == requested {
			if v, e := strconv.Atoi(s.capability("vCPUs")); e == nil && v > 0 {
				minVCPU = v
			}
			if m, e := strconv.ParseFloat(s.capability("MemoryGB"), 64); e == nil {
				minMem = m
			}
		}
	}

	best := ""
	bestVCPU, bestMem := 0, 0.0
	for _, s := range skus {
		if !s.available() || !azureGeneralPurpose(s.Name) {
			continue
		}
		v, _ := strconv.Atoi(s.capability("vCPUs"))
		m, _ := strconv.ParseFloat(s.capability("MemoryGB"), 64)
		if v < minVCPU || m < minMem {
			continue
		}
		// Smallest adequate size wins; ties broken by memory then name for determinism.
		if best == "" || v < bestVCPU ||
			(v == bestVCPU && m < bestMem) ||
			(v == bestVCPU && m == bestMem && s.Name < best) {
			best, bestVCPU, bestMem = s.Name, v, m
		}
	}
	if best == "" {
		return "", fmt.Errorf("no available general-purpose VM size in %s meets %d vCPU / %.0f GB", location, minVCPU, minMem)
	}
	return best, nil
}

// withAzureSize returns a copy of args with the --size value replaced.
func withAzureSize(args []string, size string) []string {
	out := append([]string(nil), args...)
	for i := 0; i+1 < len(out); i++ {
		if out[i] == "--size" {
			out[i+1] = size
			return out
		}
	}
	return out
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
		if isVMNotFound(err, vmID) {
			return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
		}
		return nil, wrapExecError("az vm show", err)
	}

	var result struct {
		Name       string `json:"name"`
		PowerState string `json:"powerState"`
		PublicIps  string `json:"publicIps"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	// Any non-running power state (deallocating/deallocated/stopping/stopped) is
	// terminated-or-terminating; a substring match catches the transitional states
	// too, so a shutting-down VM isn't reported healthy.
	state := VMStateRunning
	if ps := strings.ToLower(result.PowerState); strings.Contains(ps, "dealloc") || strings.Contains(ps, "stop") {
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
	assoc, err := a.gatherVMResources(ctx, vmID)
	if err != nil {
		// Already gone — teardown is idempotent (matches OCI + the GetVM contract).
		if isVMNotFound(err, vmID) {
			return nil
		}
		// Deleting the VM now would orphan its untagged OS disk / NIC / public IP
		// (gc can't reap them). Abort: the VM itself is dispatcher-tagged, so it
		// survives and a later teardown or `dispatcher gc` reaps it together with
		// its satellites via this cascade.
		return fmt.Errorf("azure: could not enumerate VM %q satellite resources; aborting delete to avoid an untagged leak: %w", vmID, err)
	}

	if _, err := runCLI(ctx, "az", "vm", "delete",
		"--resource-group", a.resourceGroup,
		"--name", vmID,
		"--yes",
		"--force-deletion", "true",
	); err != nil {
		return fmt.Errorf("az vm delete failed: %w", err)
	}

	return a.deleteAssociatedResources(ctx, assoc)
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
