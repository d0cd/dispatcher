package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// Azure list prices (eastus, USD). Rough list rates for cost visibility, not
// billing-accurate quotes.
const (
	azureSnapshotRatePerGBMonth = 0.05
	azurePublicIPMonthly        = 0.005 * gcpMonthlyHours
)

// azureDiskRatePerGBMonth maps a managed-disk SKU to an approximate $/GB-month.
var azureDiskRatePerGBMonth = map[string]float64{
	"Standard_LRS":    0.045, // Standard HDD
	"StandardSSD_LRS": 0.075,
	"Premium_LRS":     0.135,
	"PremiumV2_LRS":   0.135,
	"UltraSSD_LRS":    0.150,
}

const azureDiskRateDefault = 0.075

// azureVMResources holds the ids of a VM's auto-created satellite resources, in
// no particular order; deleteAssociatedResources sequences them.
type azureVMResources struct {
	osDiskID  string
	nicIDs    []string
	publicIPs []string
	nsgs      []string
	vnets     []string
}

// gatherVMResources reads a VM's associated resource ids (OS disk, NICs, and via
// each NIC its public IP and NSG). The top-level enumeration is retried and
// returns an error on persistent failure — these ids are the only handle on
// Azure's untagged satellites, so the caller must not delete the VM without them.
// The per-NIC drill-down is best-effort (a missed IP is one leaked address, not
// the whole cascade).
func (a *AzureProvider) gatherVMResources(ctx context.Context, rg, vmID string) (azureVMResources, error) {
	var out azureVMResources
	// Retry the enumeration: the disk/NIC/IP ids captured here are the ONLY way
	// teardown can reap Azure's auto-created (untagged) satellites, so a single
	// transient `az vm show` must not cause a permanent leak.
	var raw []byte
	err := Retry(ctx, DefaultRetry, IsTransient, func() error {
		o, e := runCLI(ctx, "az", "vm", "show",
			"--resource-group", rg, "--name", vmID, "--output", "json")
		if e != nil {
			return wrapExecError("az vm show", e)
		}
		raw = o
		return nil
	})
	if err != nil {
		return out, err
	}
	var vm struct {
		StorageProfile struct {
			OsDisk struct {
				ManagedDisk struct {
					ID string `json:"id"`
				} `json:"managedDisk"`
			} `json:"osDisk"`
		} `json:"storageProfile"`
		NetworkProfile struct {
			NetworkInterfaces []struct {
				ID string `json:"id"`
			} `json:"networkInterfaces"`
		} `json:"networkProfile"`
	}
	if err := json.Unmarshal(raw, &vm); err != nil {
		return out, fmt.Errorf("parse az vm show: %w", err)
	}
	out.osDiskID = vm.StorageProfile.OsDisk.ManagedDisk.ID
	for _, ni := range vm.NetworkProfile.NetworkInterfaces {
		if ni.ID == "" {
			continue
		}
		out.nicIDs = append(out.nicIDs, ni.ID)
		// The NIC's public-IP and NSG ids are the ONLY handle on those untagged,
		// still-billing satellites. Retry a transient throttle/503 (like the
		// top-level enumeration) and abort on a persistent failure rather than
		// silently skip and leak the static IP — the VM stays tagged for gc.
		var nicRaw []byte
		if err := Retry(ctx, DefaultRetry, IsTransient, func() error {
			o, e := runCLI(ctx, "az", "network", "nic", "show", "--ids", ni.ID, "--output", "json")
			if e != nil {
				return e
			}
			nicRaw = o
			return nil
		}); err != nil {
			return out, fmt.Errorf("enumerate NIC %q: %w", ni.ID, err)
		}
		var nic struct {
			IPConfigurations []struct {
				PublicIPAddress struct {
					ID string `json:"id"`
				} `json:"publicIPAddress"`
				Subnet struct {
					ID string `json:"id"`
				} `json:"subnet"`
			} `json:"ipConfigurations"`
			NetworkSecurityGroup struct {
				ID string `json:"id"`
			} `json:"networkSecurityGroup"`
		}
		if err := json.Unmarshal(nicRaw, &nic); err != nil {
			continue
		}
		for _, ipc := range nic.IPConfigurations {
			if ipc.PublicIPAddress.ID != "" {
				out.publicIPs = append(out.publicIPs, ipc.PublicIPAddress.ID)
			}
			// The subnet id embeds the VNet id (.../virtualNetworks/<v>/subnets/<s>).
			if i := strings.Index(ipc.Subnet.ID, "/subnets/"); i >= 0 {
				vnet := ipc.Subnet.ID[:i]
				if !slices.Contains(out.vnets, vnet) {
					out.vnets = append(out.vnets, vnet)
				}
			}
		}
		if nic.NetworkSecurityGroup.ID != "" {
			out.nsgs = append(out.nsgs, nic.NetworkSecurityGroup.ID)
		}
	}
	return out, nil
}

// deleteAssociatedResources deletes a VM's satellites in dependency order: NICs
// (freed once the VM is gone), then the public IPs and NSGs they referenced,
// then the OS disk, then the VNet. The VNet delete is best-effort and last: it
// succeeds only for a per-run VNet the departing VM emptied, and harmlessly
// fails (dependency in use) for a VNet still shared by other resources.
func (a *AzureProvider) deleteAssociatedResources(ctx context.Context, r azureVMResources) error {
	// Each delete retries transient failures — a single throttle/503 at this step
	// is exactly what would otherwise permanently leak an untagged billing
	// satellite. Failure of a BILLING satellite (OS disk / public IP) is surfaced
	// with its resource id so the operator can delete it by hand: by the time we
	// get here the VM is already gone, so neither a DestroyVM retry (its
	// gatherVMResources `az vm show` now fails) nor `dispatcher gc` (these
	// satellites are untagged, hence not dispatcher-owned) can reclaim it.
	// NIC/NSG/VNet are best-effort (free, or the shared-VNet delete harmlessly
	// fails when still in use).
	type item struct {
		id      string
		billing bool
	}
	var items []item
	for _, id := range r.nicIDs {
		items = append(items, item{id, false})
	}
	for _, id := range r.publicIPs {
		items = append(items, item{id, true})
	}
	for _, id := range r.nsgs {
		items = append(items, item{id, false})
	}
	if r.osDiskID != "" {
		items = append(items, item{r.osDiskID, true})
	}
	for _, id := range r.vnets {
		items = append(items, item{id, false})
	}

	var leaked []string
	for _, it := range items {
		id := it.id
		err := Retry(ctx, DefaultRetry, IsTransient, func() error {
			_, e := runCLI(ctx, "az", "resource", "delete", "--ids", id)
			return e
		})
		if err != nil && it.billing {
			leaked = append(leaked, id)
		}
	}
	if len(leaked) > 0 {
		return fmt.Errorf("azure teardown could not delete billing resources; they keep billing, are untagged, and cannot be auto-reaped (VM already deleted) — delete by hand: %s", strings.Join(leaked, ", "))
	}
	return nil
}

// ListResources enumerates billable Azure resources in the resource group for
// the cost audit and GC: VMs, managed disks, public IPs, and snapshots. The VM
// list is reaping-critical and fails loud; auxiliary kinds are best-effort. The
// OS disk and public IP a VM auto-creates are untagged, so they surface as
// external (visible, not reaped) — teardown's cascade is what prevents the leak.
func (a *AzureProvider) ListResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := a.listVMResources(ctx)
	if err != nil {
		return nil, err
	}
	for _, step := range []func(context.Context) ([]adapter.ResourceInfo, error){
		a.listDiskResources, a.listPublicIPResources, a.listSnapshotResources,
	} {
		if rs, err := step(ctx); err == nil {
			out = append(out, rs...)
		}
	}
	return out, nil
}

// DestroyResource deletes a single Azure resource by kind. Callers (the adapter)
// enforce the dispatcher-owned boundary first. Instances route through DestroyVM
// so the associated-resource cascade runs.
func (a *AzureProvider) DestroyResource(ctx context.Context, res adapter.ResourceInfo) error {
	if !res.DispatcherOwned() {
		return fmt.Errorf("refusing to destroy %s %q: not dispatcher-owned", res.Kind, res.ResourceID)
	}
	// Route to the RG the resource actually lives in (gc scans subscription-wide),
	// falling back to the adapter's own group. Validate both so neither can inject
	// argv.
	rg := res.Scope
	if rg == "" {
		rg = a.resourceGroup
	}
	if !destroyArgsSafe(res.ResourceID, rg) {
		return fmt.Errorf("azure: refusing to destroy %q: unsafe resource id or scope", res.ResourceID)
	}
	var args []string
	switch res.Kind {
	case adapter.ResourceInstance:
		return a.destroyVMInRG(ctx, rg, res.ResourceID)
	case adapter.ResourceDisk:
		args = []string{"disk", "delete", "--resource-group", rg, "--name", res.ResourceID, "--yes"}
	case adapter.ResourceAddress:
		args = []string{"network", "public-ip", "delete", "--resource-group", rg, "--name", res.ResourceID}
	case adapter.ResourceSnapshot:
		args = []string{"snapshot", "delete", "--resource-group", rg, "--name", res.ResourceID}
	default:
		return fmt.Errorf("azure: cannot destroy resource of kind %q", res.Kind)
	}
	if _, err := runCLI(ctx, "az", args...); err != nil {
		return fmt.Errorf("az %s delete failed: %w", res.Kind, err)
	}
	return nil
}

// includeCrossRG decides whether a subscription-wide-listed resource belongs in
// the gc report. gc scans every resource group so a dispatcher-owned resource
// leaked into another RG is still found; non-owned resources are only surfaced
// from the configured RG so a large subscription doesn't flood the report with
// unrelated infrastructure.
func (a *AzureProvider) includeCrossRG(rg string, tags map[string]string) bool {
	return tags["dispatcher"] == "true" || rg == a.resourceGroup
}

// azureRegionOr returns the resource's own location, or the adapter default when
// the listing didn't carry one.
func (a *AzureProvider) azureRegionOr(location string) string {
	if location != "" {
		return location
	}
	return a.location
}

func (a *AzureProvider) listVMResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "az", "vm", "list", "--show-details", "--output", "json")
	if err != nil {
		return nil, wrapExecError("az vm list", err)
	}
	var vms []struct {
		Name            string `json:"name"`
		PowerState      string `json:"powerState"`
		ResourceGroup   string `json:"resourceGroup"`
		Location        string `json:"location"`
		HardwareProfile struct {
			VMSize string `json:"vmSize"`
		} `json:"hardwareProfile"`
		Tags map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(out, &vms); err != nil {
		return nil, fmt.Errorf("parse az vms: %w", err)
	}
	catalog := NewCatalog()
	var res []adapter.ResourceInfo
	for _, vm := range vms {
		// Positive allowlist: only enumerate a VM in a known billing state
		// (running, or stopped-but-allocated). A deallocated VM isn't compute-
		// billing (its disk is enumerated separately), and an empty/unrecognized
		// powerState is skipped rather than treated as live-and-reapable.
		ps := strings.ToLower(vm.PowerState)
		if !strings.Contains(ps, "running") && !strings.Contains(ps, "stopped") {
			continue
		}
		if !a.includeCrossRG(vm.ResourceGroup, vm.Tags) {
			continue
		}
		res = append(res, adapter.ResourceInfo{
			ResourceID:   vm.Name,
			Provider:     string(ProviderAzure),
			Kind:         adapter.ResourceInstance,
			Region:       a.azureRegionOr(vm.Location),
			Scope:        vm.ResourceGroup,
			InstanceType: vm.HardwareProfile.VMSize,
			RunID:        vm.Tags["dispatcher-run-id"],
			Tags:         vm.Tags,
			MonthlyUSD:   catalog.PriceByName(ProviderAzure, vm.HardwareProfile.VMSize) * gcpMonthlyHours,
		})
	}
	return res, nil
}

func (a *AzureProvider) listDiskResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "az", "disk", "list", "--output", "json")
	if err != nil {
		return nil, err
	}
	var disks []struct {
		Name          string `json:"name"`
		ResourceGroup string `json:"resourceGroup"`
		Location      string `json:"location"`
		DiskSizeGb    int    `json:"diskSizeGb"`
		Sku           struct {
			Name string `json:"name"`
		} `json:"sku"`
		Tags map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(out, &disks); err != nil {
		return nil, fmt.Errorf("parse az disks: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, d := range disks {
		if !a.includeCrossRG(d.ResourceGroup, d.Tags) {
			continue
		}
		rate, ok := azureDiskRatePerGBMonth[d.Sku.Name]
		if !ok {
			rate = azureDiskRateDefault
		}
		res = append(res, adapter.ResourceInfo{
			ResourceID: d.Name,
			Provider:   string(ProviderAzure),
			Kind:       adapter.ResourceDisk,
			Region:     a.azureRegionOr(d.Location),
			Scope:      d.ResourceGroup,
			RunID:      d.Tags["dispatcher-run-id"],
			Tags:       d.Tags,
			MonthlyUSD: float64(d.DiskSizeGb) * rate,
		})
	}
	return res, nil
}

func (a *AzureProvider) listPublicIPResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "az", "network", "public-ip", "list", "--output", "json")
	if err != nil {
		return nil, err
	}
	var ips []struct {
		Name          string            `json:"name"`
		ResourceGroup string            `json:"resourceGroup"`
		Location      string            `json:"location"`
		Tags          map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(out, &ips); err != nil {
		return nil, fmt.Errorf("parse az public ips: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, ip := range ips {
		if !a.includeCrossRG(ip.ResourceGroup, ip.Tags) {
			continue
		}
		res = append(res, adapter.ResourceInfo{
			ResourceID: ip.Name,
			Provider:   string(ProviderAzure),
			Kind:       adapter.ResourceAddress,
			Region:     a.azureRegionOr(ip.Location),
			Scope:      ip.ResourceGroup,
			RunID:      ip.Tags["dispatcher-run-id"],
			Tags:       ip.Tags,
			MonthlyUSD: azurePublicIPMonthly,
		})
	}
	return res, nil
}

func (a *AzureProvider) listSnapshotResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "az", "snapshot", "list", "--output", "json")
	if err != nil {
		return nil, err
	}
	var snaps []struct {
		Name          string            `json:"name"`
		ResourceGroup string            `json:"resourceGroup"`
		Location      string            `json:"location"`
		DiskSizeGb    int               `json:"diskSizeGb"`
		Tags          map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("parse az snapshots: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, s := range snaps {
		if !a.includeCrossRG(s.ResourceGroup, s.Tags) {
			continue
		}
		res = append(res, adapter.ResourceInfo{
			ResourceID: s.Name,
			Provider:   string(ProviderAzure),
			Kind:       adapter.ResourceSnapshot,
			Region:     a.azureRegionOr(s.Location),
			Scope:      s.ResourceGroup,
			RunID:      s.Tags["dispatcher-run-id"],
			Tags:       s.Tags,
			MonthlyUSD: float64(s.DiskSizeGb) * azureSnapshotRatePerGBMonth,
		})
	}
	return res, nil
}
