package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// gcpMonthlyHours approximates a 30-day month for turning hourly rates into a
// monthly figure.
const gcpMonthlyHours = 730.0

// GCP storage list prices (us-central1, USD). These are rough list rates for
// cost visibility, not billing-accurate quotes — enough to flag a resource
// that is quietly costing money.
const (
	gcpImageRatePerGBMonth    = 0.050 // custom image storage
	gcpSnapshotRatePerGBMonth = 0.026 // snapshot storage
	gcpAddressMonthlyReserved = 0.010 * gcpMonthlyHours
)

// gcpDiskRatePerGBMonth maps a persistent-disk type to its $/GB-month rate.
var gcpDiskRatePerGBMonth = map[string]float64{
	"pd-standard":        0.040,
	"pd-balanced":        0.100,
	"pd-ssd":             0.170,
	"pd-extreme":         0.125,
	"hyperdisk-balanced": 0.081,
}

const gcpDiskRateDefault = 0.100

// ListResources enumerates billable GCP resources for the cost audit and GC.
// The instances list is reaping-critical and fails loud; the auxiliary billable
// kinds (disks/images/snapshots/addresses) are best-effort so a single denied
// list (e.g. no snapshots permission) can never blind GC to reapable instances
// — missing one only reduces cost visibility, never causes wrong reaping.
func (g *GCPProvider) ListResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := g.listInstanceResources(ctx)
	if err != nil {
		return nil, err
	}
	for _, step := range []func(context.Context) ([]adapter.ResourceInfo, error){
		g.listDiskResources, g.listImageResources, g.listSnapshotResources, g.listAddressResources,
	} {
		if rs, err := step(ctx); err == nil {
			out = append(out, rs...)
		}
	}
	return out, nil
}

// DestroyResource deletes a single GCP resource by kind. Callers (the adapter)
// enforce the dispatcher-owned boundary before reaching here.
func (g *GCPProvider) DestroyResource(ctx context.Context, res adapter.ResourceInfo) error {
	var args []string
	switch res.Kind {
	case adapter.ResourceInstance:
		args = []string{"compute", "instances", "delete", res.ResourceID, "--zone", res.Region, "--quiet"}
	case adapter.ResourceDisk:
		args = []string{"compute", "disks", "delete", res.ResourceID, "--zone", res.Region, "--quiet"}
	case adapter.ResourceImage:
		args = []string{"compute", "images", "delete", res.ResourceID, "--quiet"}
	case adapter.ResourceSnapshot:
		args = []string{"compute", "snapshots", "delete", res.ResourceID, "--quiet"}
	case adapter.ResourceAddress:
		args = []string{"compute", "addresses", "delete", res.ResourceID, "--region", res.Region, "--quiet"}
	default:
		return fmt.Errorf("gcp: cannot destroy resource of kind %q", res.Kind)
	}
	if g.project != "" {
		args = append(args, "--project", g.project)
	}
	if _, err := runCLI(ctx, "gcloud", args...); err != nil {
		return fmt.Errorf("gcloud %s delete failed: %w", res.Kind, err)
	}
	return nil
}

func (g *GCPProvider) listArgs(kind string, extra ...string) []string {
	args := append([]string{"compute", kind, "list"}, extra...)
	args = append(args, "--format", "json")
	if g.project != "" {
		args = append(args, "--project", g.project)
	}
	return args
}

func (g *GCPProvider) listInstanceResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "gcloud", g.listArgs("instances")...)
	if err != nil {
		return nil, wrapExecError("gcloud compute instances list", err)
	}
	var instances []struct {
		Name        string            `json:"name"`
		MachineType string            `json:"machineType"`
		Status      string            `json:"status"`
		Zone        string            `json:"zone"`
		Labels      map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &instances); err != nil {
		return nil, fmt.Errorf("parse gcp instances: %w", err)
	}
	catalog := NewCatalog()
	var res []adapter.ResourceInfo
	for _, in := range instances {
		if in.Status == "TERMINATED" {
			continue // stopped: not billing for compute
		}
		machineType := gcpLastSegment(in.MachineType)
		res = append(res, adapter.ResourceInfo{
			ResourceID:   in.Name,
			Provider:     string(ProviderGCP),
			Kind:         adapter.ResourceInstance,
			Region:       gcpLastSegment(in.Zone),
			InstanceType: machineType,
			RunID:        in.Labels["dispatcher-run-id"],
			Tags:         in.Labels,
			MonthlyUSD:   catalog.PriceByName(ProviderGCP, machineType) * gcpMonthlyHours,
		})
	}
	return res, nil
}

func (g *GCPProvider) listDiskResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "gcloud", g.listArgs("disks")...)
	if err != nil {
		return nil, err
	}
	var disks []struct {
		Name   string            `json:"name"`
		SizeGb string            `json:"sizeGb"`
		Type   string            `json:"type"`
		Zone   string            `json:"zone"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &disks); err != nil {
		return nil, fmt.Errorf("parse gcp disks: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, d := range disks {
		sizeGb, _ := strconv.ParseFloat(d.SizeGb, 64)
		rate, ok := gcpDiskRatePerGBMonth[gcpLastSegment(d.Type)]
		if !ok {
			rate = gcpDiskRateDefault
		}
		res = append(res, adapter.ResourceInfo{
			ResourceID: d.Name,
			Provider:   string(ProviderGCP),
			Kind:       adapter.ResourceDisk,
			Region:     gcpLastSegment(d.Zone),
			RunID:      d.Labels["dispatcher-run-id"],
			Tags:       d.Labels,
			MonthlyUSD: sizeGb * rate,
		})
	}
	return res, nil
}

func (g *GCPProvider) listImageResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "gcloud", g.listArgs("images", "--no-standard-images")...)
	if err != nil {
		return nil, err
	}
	var images []struct {
		Name             string            `json:"name"`
		ArchiveSizeBytes string            `json:"archiveSizeBytes"`
		Labels           map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &images); err != nil {
		return nil, fmt.Errorf("parse gcp images: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, im := range images {
		bytes, _ := strconv.ParseFloat(im.ArchiveSizeBytes, 64)
		res = append(res, adapter.ResourceInfo{
			ResourceID: im.Name,
			Provider:   string(ProviderGCP),
			Kind:       adapter.ResourceImage,
			RunID:      im.Labels["dispatcher-run-id"],
			Tags:       im.Labels,
			MonthlyUSD: gcpBytesToGiB(bytes) * gcpImageRatePerGBMonth,
		})
	}
	return res, nil
}

func (g *GCPProvider) listSnapshotResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "gcloud", g.listArgs("snapshots")...)
	if err != nil {
		return nil, err
	}
	var snaps []struct {
		Name         string            `json:"name"`
		StorageBytes string            `json:"storageBytes"`
		Labels       map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("parse gcp snapshots: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, s := range snaps {
		bytes, _ := strconv.ParseFloat(s.StorageBytes, 64)
		res = append(res, adapter.ResourceInfo{
			ResourceID: s.Name,
			Provider:   string(ProviderGCP),
			Kind:       adapter.ResourceSnapshot,
			RunID:      s.Labels["dispatcher-run-id"],
			Tags:       s.Labels,
			MonthlyUSD: gcpBytesToGiB(bytes) * gcpSnapshotRatePerGBMonth,
		})
	}
	return res, nil
}

func (g *GCPProvider) listAddressResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "gcloud", g.listArgs("addresses")...)
	if err != nil {
		return nil, err
	}
	var addrs []struct {
		Name   string            `json:"name"`
		Status string            `json:"status"`
		Region string            `json:"region"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &addrs); err != nil {
		return nil, fmt.Errorf("parse gcp addresses: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, a := range addrs {
		// An IN_USE address is free while attached to a running instance; only a
		// RESERVED (unattached) static IP bills on its own. Cost only the latter
		// so the total isn't double-counted against the instance.
		monthly := 0.0
		if a.Status == "RESERVED" {
			monthly = gcpAddressMonthlyReserved
		}
		res = append(res, adapter.ResourceInfo{
			ResourceID: a.Name,
			Provider:   string(ProviderGCP),
			Kind:       adapter.ResourceAddress,
			Region:     gcpLastSegment(a.Region),
			RunID:      a.Labels["dispatcher-run-id"],
			Tags:       a.Labels,
			MonthlyUSD: monthly,
		})
	}
	return res, nil
}

// gcpLastSegment returns the trailing path segment of a GCP self-link URL (e.g.
// ".../zones/us-central1-a" -> "us-central1-a"). A bare value passes through.
func gcpLastSegment(url string) string {
	if i := strings.LastIndexByte(url, '/'); i >= 0 {
		return url[i+1:]
	}
	return url
}

func gcpBytesToGiB(b float64) float64 { return b / (1024 * 1024 * 1024) }
