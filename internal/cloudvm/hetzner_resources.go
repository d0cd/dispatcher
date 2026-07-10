package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// Hetzner list prices (EU, USD-ish). Rough list rates for cost visibility, not
// billing-accurate quotes.
const (
	hetznerVolumeRatePerGBMonth   = 0.05
	hetznerSnapshotRatePerGBMonth = 0.013
	hetznerPrimaryIPMonthly       = 0.60
	hetznerFloatingIPMonthly      = 1.30
)

// ListResources enumerates billable Hetzner resources for the cost audit and
// GC: servers, volumes, primary/floating IPs, snapshots, and dispatcher-owned
// firewalls. The server list is reaping-critical and fails loud; auxiliary
// kinds are best-effort. Dispatcher creates only servers (and free per-run
// firewalls), so the other kinds surface as external cost visibility.
func (h *HetznerProvider) ListResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := h.listServerResources(ctx)
	if err != nil {
		return nil, err
	}
	for _, step := range []func(context.Context) ([]adapter.ResourceInfo, error){
		h.listVolumeResources, h.listPrimaryIPResources, h.listFloatingIPResources,
		h.listSnapshotResources, h.listFirewallResources,
	} {
		if rs, err := step(ctx); err == nil {
			out = append(out, rs...)
		}
	}
	return out, nil
}

// DestroyResource deletes a single Hetzner resource by kind. Callers (the
// adapter) enforce the dispatcher-owned boundary first. Servers route through
// DestroyVM so the per-run firewall and SSH key are cleaned up too.
func (h *HetznerProvider) DestroyResource(ctx context.Context, res adapter.ResourceInfo) error {
	if !res.DispatcherOwned() {
		return fmt.Errorf("refusing to destroy %s %q: not dispatcher-owned", res.Kind, res.ResourceID)
	}
	var args []string
	switch res.Kind {
	case adapter.ResourceInstance:
		return h.DestroyVM(ctx, res.ResourceID)
	case adapter.ResourceDisk:
		args = []string{"volume", "delete", res.ResourceID}
	case adapter.ResourceSnapshot:
		args = []string{"image", "delete", res.ResourceID}
	case adapter.ResourceFirewall:
		args = []string{"firewall", "delete", res.ResourceID}
	case adapter.ResourceAddress:
		// Primary and floating IPs are separate hcloud resources; the tag we set
		// at enumeration says which delete verb to use.
		verb := res.Tags[hetznerIPKindTag]
		if verb == "" {
			verb = "primary-ip"
		}
		args = []string{verb, "delete", res.ResourceID}
	default:
		return fmt.Errorf("hetzner: cannot destroy resource of kind %q", res.Kind)
	}
	if _, err := runCLI(ctx, "hcloud", args...); err != nil {
		return fmt.Errorf("hcloud %s delete failed: %w", res.Kind, err)
	}
	return nil
}

// hetznerIPKindTag records, on an enumerated address resource, which hcloud
// resource it is ("primary-ip" or "floating-ip") so DestroyResource picks the
// right delete verb. It is an internal marker, not a cloud label.
const hetznerIPKindTag = "_hcloud-ip-kind"

func (h *HetznerProvider) listServerResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "hcloud", "server", "list", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("hcloud server list: %w", err)
	}
	var servers []struct {
		ID         int    `json:"id"`
		Name       string `json:"name"`
		ServerType struct {
			Name string `json:"name"`
		} `json:"server_type"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &servers); err != nil {
		return nil, fmt.Errorf("parse hcloud servers: %w", err)
	}
	catalog := NewCatalog()
	var res []adapter.ResourceInfo
	for _, s := range servers {
		res = append(res, adapter.ResourceInfo{
			ResourceID:   fmt.Sprintf("%d", s.ID),
			Provider:     string(ProviderHetzner),
			Kind:         adapter.ResourceInstance,
			InstanceType: s.ServerType.Name,
			RunID:        s.Labels["dispatcher-run-id"],
			Tags:         s.Labels,
			MonthlyUSD:   catalog.PriceByName(ProviderHetzner, s.ServerType.Name) * gcpMonthlyHours,
		})
	}
	return res, nil
}

func (h *HetznerProvider) listVolumeResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "hcloud", "volume", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var vols []struct {
		ID     int               `json:"id"`
		Size   int               `json:"size"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &vols); err != nil {
		return nil, fmt.Errorf("parse hcloud volumes: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, v := range vols {
		res = append(res, adapter.ResourceInfo{
			ResourceID: fmt.Sprintf("%d", v.ID),
			Provider:   string(ProviderHetzner),
			Kind:       adapter.ResourceDisk,
			RunID:      v.Labels["dispatcher-run-id"],
			Tags:       v.Labels,
			MonthlyUSD: float64(v.Size) * hetznerVolumeRatePerGBMonth,
		})
	}
	return res, nil
}

func (h *HetznerProvider) listPrimaryIPResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "hcloud", "primary-ip", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var ips []struct {
		ID     int               `json:"id"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &ips); err != nil {
		return nil, fmt.Errorf("parse hcloud primary ips: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, ip := range ips {
		res = append(res, adapter.ResourceInfo{
			ResourceID: fmt.Sprintf("%d", ip.ID),
			Provider:   string(ProviderHetzner),
			Kind:       adapter.ResourceAddress,
			RunID:      ip.Labels["dispatcher-run-id"],
			Tags:       mergeTag(ip.Labels, hetznerIPKindTag, "primary-ip"),
			MonthlyUSD: hetznerPrimaryIPMonthly,
		})
	}
	return res, nil
}

func (h *HetznerProvider) listFloatingIPResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "hcloud", "floating-ip", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var ips []struct {
		ID     int               `json:"id"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &ips); err != nil {
		return nil, fmt.Errorf("parse hcloud floating ips: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, ip := range ips {
		res = append(res, adapter.ResourceInfo{
			ResourceID: fmt.Sprintf("%d", ip.ID),
			Provider:   string(ProviderHetzner),
			Kind:       adapter.ResourceAddress,
			RunID:      ip.Labels["dispatcher-run-id"],
			Tags:       mergeTag(ip.Labels, hetznerIPKindTag, "floating-ip"),
			MonthlyUSD: hetznerFloatingIPMonthly,
		})
	}
	return res, nil
}

func (h *HetznerProvider) listSnapshotResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "hcloud", "image", "list", "--type", "snapshot", "-o", "json")
	if err != nil {
		return nil, err
	}
	var images []struct {
		ID        int               `json:"id"`
		ImageSize float64           `json:"image_size"`
		Labels    map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &images); err != nil {
		return nil, fmt.Errorf("parse hcloud snapshots: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, im := range images {
		res = append(res, adapter.ResourceInfo{
			ResourceID: fmt.Sprintf("%d", im.ID),
			Provider:   string(ProviderHetzner),
			Kind:       adapter.ResourceSnapshot,
			RunID:      im.Labels["dispatcher-run-id"],
			Tags:       im.Labels,
			MonthlyUSD: im.ImageSize * hetznerSnapshotRatePerGBMonth,
		})
	}
	return res, nil
}

// listFirewallResources lists only dispatcher-labeled firewalls: they are free,
// so enumerating every firewall would be noise. The value is reaping a per-run
// firewall that leaked when teardown's best-effort delete failed.
func (h *HetznerProvider) listFirewallResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "hcloud", "firewall", "list", "--selector", "dispatcher=true", "-o", "json")
	if err != nil {
		return nil, err
	}
	var firewalls []struct {
		ID     int               `json:"id"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &firewalls); err != nil {
		return nil, fmt.Errorf("parse hcloud firewalls: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, fw := range firewalls {
		res = append(res, adapter.ResourceInfo{
			ResourceID: fmt.Sprintf("%d", fw.ID),
			Provider:   string(ProviderHetzner),
			Kind:       adapter.ResourceFirewall,
			RunID:      fw.Labels["dispatcher-run-id"],
			Tags:       fw.Labels,
		})
	}
	return res, nil
}

// mergeTag returns a copy of labels with key=value added, without mutating the
// original map.
func mergeTag(labels map[string]string, key, value string) map[string]string {
	out := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		out[k] = v
	}
	out[key] = value
	return out
}
