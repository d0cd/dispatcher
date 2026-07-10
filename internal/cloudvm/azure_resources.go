package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
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
// each NIC its public IP and NSG). Best-effort: any failure yields whatever was
// found so teardown still deletes the VM.
func (a *AzureProvider) gatherVMResources(ctx context.Context, vmID string) azureVMResources {
	var out azureVMResources
	raw, err := runCLI(ctx, "az", "vm", "show",
		"--resource-group", a.resourceGroup, "--name", vmID, "--output", "json")
	if err != nil {
		return out
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
		return out
	}
	out.osDiskID = vm.StorageProfile.OsDisk.ManagedDisk.ID
	for _, ni := range vm.NetworkProfile.NetworkInterfaces {
		if ni.ID == "" {
			continue
		}
		out.nicIDs = append(out.nicIDs, ni.ID)
		nicRaw, err := runCLI(ctx, "az", "network", "nic", "show", "--ids", ni.ID, "--output", "json")
		if err != nil {
			continue
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
				if !contains(out.vnets, vnet) {
					out.vnets = append(out.vnets, vnet)
				}
			}
		}
		if nic.NetworkSecurityGroup.ID != "" {
			out.nsgs = append(out.nsgs, nic.NetworkSecurityGroup.ID)
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// deleteAssociatedResources deletes a VM's satellites in dependency order: NICs
// (freed once the VM is gone), then the public IPs and NSGs they referenced,
// then the OS disk, then the VNet. The VNet delete is best-effort and last: it
// succeeds only for a per-run VNet the departing VM emptied, and harmlessly
// fails (dependency in use) for a VNet still shared by other resources.
func (a *AzureProvider) deleteAssociatedResources(ctx context.Context, r azureVMResources) {
	ordered := append([]string{}, r.nicIDs...)
	ordered = append(ordered, r.publicIPs...)
	ordered = append(ordered, r.nsgs...)
	if r.osDiskID != "" {
		ordered = append(ordered, r.osDiskID)
	}
	ordered = append(ordered, r.vnets...)
	for _, id := range ordered {
		_, _ = runCLI(ctx, "az", "resource", "delete", "--ids", id)
	}
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
	if !destroyArgsSafe(res.ResourceID, "") {
		return fmt.Errorf("azure: refusing to destroy %q: unsafe resource id", res.ResourceID)
	}
	var args []string
	switch res.Kind {
	case adapter.ResourceInstance:
		return a.DestroyVM(ctx, res.ResourceID)
	case adapter.ResourceDisk:
		args = []string{"disk", "delete", "--resource-group", a.resourceGroup, "--name", res.ResourceID, "--yes"}
	case adapter.ResourceAddress:
		args = []string{"network", "public-ip", "delete", "--resource-group", a.resourceGroup, "--name", res.ResourceID}
	case adapter.ResourceSnapshot:
		args = []string{"snapshot", "delete", "--resource-group", a.resourceGroup, "--name", res.ResourceID}
	default:
		return fmt.Errorf("azure: cannot destroy resource of kind %q", res.Kind)
	}
	if _, err := runCLI(ctx, "az", args...); err != nil {
		return fmt.Errorf("az %s delete failed: %w", res.Kind, err)
	}
	return nil
}

func (a *AzureProvider) listVMResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "az", "vm", "list", "--resource-group", a.resourceGroup, "--show-details", "--output", "json")
	if err != nil {
		return nil, wrapExecError("az vm list", err)
	}
	var vms []struct {
		Name            string `json:"name"`
		PowerState      string `json:"powerState"`
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
		res = append(res, adapter.ResourceInfo{
			ResourceID:   vm.Name,
			Provider:     string(ProviderAzure),
			Kind:         adapter.ResourceInstance,
			Region:       a.location,
			InstanceType: vm.HardwareProfile.VMSize,
			RunID:        vm.Tags["dispatcher-run-id"],
			Tags:         vm.Tags,
			MonthlyUSD:   catalog.PriceByName(ProviderAzure, vm.HardwareProfile.VMSize) * gcpMonthlyHours,
		})
	}
	return res, nil
}

func (a *AzureProvider) listDiskResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "az", "disk", "list", "--resource-group", a.resourceGroup, "--output", "json")
	if err != nil {
		return nil, err
	}
	var disks []struct {
		Name       string `json:"name"`
		DiskSizeGb int    `json:"diskSizeGb"`
		Sku        struct {
			Name string `json:"name"`
		} `json:"sku"`
		Tags map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(out, &disks); err != nil {
		return nil, fmt.Errorf("parse az disks: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, d := range disks {
		rate, ok := azureDiskRatePerGBMonth[d.Sku.Name]
		if !ok {
			rate = azureDiskRateDefault
		}
		res = append(res, adapter.ResourceInfo{
			ResourceID: d.Name,
			Provider:   string(ProviderAzure),
			Kind:       adapter.ResourceDisk,
			Region:     a.location,
			RunID:      d.Tags["dispatcher-run-id"],
			Tags:       d.Tags,
			MonthlyUSD: float64(d.DiskSizeGb) * rate,
		})
	}
	return res, nil
}

func (a *AzureProvider) listPublicIPResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "az", "network", "public-ip", "list", "--resource-group", a.resourceGroup, "--output", "json")
	if err != nil {
		return nil, err
	}
	var ips []struct {
		Name string            `json:"name"`
		Tags map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(out, &ips); err != nil {
		return nil, fmt.Errorf("parse az public ips: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, ip := range ips {
		res = append(res, adapter.ResourceInfo{
			ResourceID: ip.Name,
			Provider:   string(ProviderAzure),
			Kind:       adapter.ResourceAddress,
			Region:     a.location,
			RunID:      ip.Tags["dispatcher-run-id"],
			Tags:       ip.Tags,
			MonthlyUSD: azurePublicIPMonthly,
		})
	}
	return res, nil
}

func (a *AzureProvider) listSnapshotResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "az", "snapshot", "list", "--resource-group", a.resourceGroup, "--output", "json")
	if err != nil {
		return nil, err
	}
	var snaps []struct {
		Name       string            `json:"name"`
		DiskSizeGb int               `json:"diskSizeGb"`
		Tags       map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("parse az snapshots: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, s := range snaps {
		res = append(res, adapter.ResourceInfo{
			ResourceID: s.Name,
			Provider:   string(ProviderAzure),
			Kind:       adapter.ResourceSnapshot,
			Region:     a.location,
			RunID:      s.Tags["dispatcher-run-id"],
			Tags:       s.Tags,
			MonthlyUSD: float64(s.DiskSizeGb) * azureSnapshotRatePerGBMonth,
		})
	}
	return res, nil
}
