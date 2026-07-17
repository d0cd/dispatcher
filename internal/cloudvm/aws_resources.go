package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// AWS list prices (us-east-1, USD). Rough list rates for cost visibility, not
// billing-accurate quotes.
const (
	awsSnapshotRatePerGBMonth = 0.05
	awsEIPMonthlyUnassociated = 0.005 * gcpMonthlyHours
)

// awsEBSRatePerGBMonth maps an EBS volume type to its $/GB-month rate.
var awsEBSRatePerGBMonth = map[string]float64{
	"gp3":      0.080,
	"gp2":      0.100,
	"io1":      0.125,
	"io2":      0.125,
	"st1":      0.045,
	"sc1":      0.015,
	"standard": 0.050,
}

const awsEBSRateDefault = 0.100

// awsTag is one {Key,Value} entry as returned by the EC2 describe APIs.
type awsTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

func awsTagsToMap(tags []awsTag) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[t.Key] = t.Value
	}
	return m
}

// ListResources enumerates billable AWS resources across ALL enabled regions
// for the cost audit and GC: instances, EBS volumes, snapshots, Elastic IPs, and
// dispatcher-owned security groups. A run can be provisioned in any region, so a
// single-region sweep would leave an orphan elsewhere billing forever, invisible
// to gc. Regions are swept concurrently. Each region is best-effort — a region
// that errors contributes nothing (gc simply won't act on it, never a wrong
// destroy); only a total failure to enumerate anything is surfaced.
func (a *AWSProvider) ListResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	regions := a.enabledRegions(ctx)

	var (
		mu      sync.Mutex
		all     []adapter.ResourceInfo
		errored int
		wg      sync.WaitGroup
	)
	for _, region := range regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			res, err := a.listRegionResources(ctx, region)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errored++
				return
			}
			all = append(all, res...)
		}(region)
	}
	wg.Wait()

	if errored == len(regions) {
		return nil, fmt.Errorf("aws: could not enumerate resources in any of %d region(s)", len(regions))
	}
	return all, nil
}

// enabledRegions lists the account's enabled regions, falling back to the
// provider's default region if discovery fails (preserving single-region
// behavior when EC2 describe-regions is unavailable).
func (a *AWSProvider) enabledRegions(ctx context.Context) []string {
	out, err := runCLI(ctx, "aws", "ec2", "describe-regions",
		"--query", "Regions[].RegionName", "--output", "json")
	if err != nil {
		return []string{a.defaultRegion}
	}
	var regions []string
	if err := json.Unmarshal(out, &regions); err != nil || len(regions) == 0 {
		return []string{a.defaultRegion}
	}
	return regions
}

// listRegionResources enumerates one region: the instance list is reaping-
// critical and fails the region loud; the auxiliary kinds are best-effort.
func (a *AWSProvider) listRegionResources(ctx context.Context, region string) ([]adapter.ResourceInfo, error) {
	out, err := a.listInstanceResources(ctx, region)
	if err != nil {
		return nil, err
	}
	for _, step := range []func(context.Context, string) ([]adapter.ResourceInfo, error){
		a.listVolumeResources, a.listSnapshotResources, a.listAddressResources, a.listSecurityGroupResources,
	} {
		if rs, err := step(ctx, region); err == nil {
			out = append(out, rs...)
		}
	}
	return out, nil
}

// DestroyResource deletes a single AWS resource by kind. The adapter enforces
// the dispatcher-owned boundary; this method re-checks it so the destructive
// call can never run on a resource dispatcher doesn't own.
func (a *AWSProvider) DestroyResource(ctx context.Context, res adapter.ResourceInfo) error {
	if !res.DispatcherOwned() {
		return fmt.Errorf("refusing to destroy %s %q: not dispatcher-owned", res.Kind, res.ResourceID)
	}
	region := res.Region
	if region == "" {
		region = a.defaultRegion
	}
	if !destroyArgsSafe(res.ResourceID, region) {
		return fmt.Errorf("aws: refusing to destroy %q: unsafe resource id or region", res.ResourceID)
	}
	var args []string
	switch res.Kind {
	case adapter.ResourceInstance:
		args = []string{"ec2", "terminate-instances", "--region", region, "--instance-ids", res.ResourceID}
	case adapter.ResourceDisk:
		args = []string{"ec2", "delete-volume", "--region", region, "--volume-id", res.ResourceID}
	case adapter.ResourceSnapshot:
		args = []string{"ec2", "delete-snapshot", "--region", region, "--snapshot-id", res.ResourceID}
	case adapter.ResourceAddress:
		args = []string{"ec2", "release-address", "--region", region, "--allocation-id", res.ResourceID}
	case adapter.ResourceFirewall:
		args = []string{"ec2", "delete-security-group", "--region", region, "--group-id", res.ResourceID}
	default:
		return fmt.Errorf("aws: cannot destroy resource of kind %q", res.Kind)
	}
	if _, err := runCLI(ctx, "aws", args...); err != nil {
		return fmt.Errorf("aws %s delete failed: %w", res.Kind, err)
	}
	return nil
}

func (a *AWSProvider) listInstanceResources(ctx context.Context, region string) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-instances", "--region", region, "--output", "json")
	if err != nil {
		return nil, wrapExecError("aws ec2 describe-instances", err)
	}
	var result struct {
		Reservations []struct {
			Instances []struct {
				InstanceId   string                `json:"InstanceId"`
				InstanceType string                `json:"InstanceType"`
				State        struct{ Name string } `json:"State"`
				Tags         []awsTag              `json:"Tags"`
			} `json:"Instances"`
		} `json:"Reservations"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse aws instances: %w", err)
	}
	catalog := NewCatalog()
	var res []adapter.ResourceInfo
	for _, r := range result.Reservations {
		for _, in := range r.Instances {
			if in.State.Name == "terminated" || in.State.Name == "shutting-down" {
				continue
			}
			tags := awsTagsToMap(in.Tags)
			// A stopped instance incurs no compute charge (only its EBS volumes
			// bill, enumerated separately) — price it at 0 so it isn't double-
			// counted with its volume. Still list it for reap visibility.
			monthly := 0.0
			if in.State.Name != "stopped" {
				monthly = catalog.PriceByName(ProviderAWS, in.InstanceType) * gcpMonthlyHours
			}
			res = append(res, adapter.ResourceInfo{
				ResourceID:   in.InstanceId,
				Provider:     string(ProviderAWS),
				Kind:         adapter.ResourceInstance,
				Region:       region,
				InstanceType: in.InstanceType,
				RunID:        tags["dispatcher-run-id"],
				Tags:         tags,
				MonthlyUSD:   monthly,
			})
		}
	}
	return res, nil
}

func (a *AWSProvider) listVolumeResources(ctx context.Context, region string) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-volumes", "--region", region, "--output", "json")
	if err != nil {
		return nil, err
	}
	var result struct {
		Volumes []struct {
			VolumeId   string   `json:"VolumeId"`
			Size       int      `json:"Size"`
			VolumeType string   `json:"VolumeType"`
			Tags       []awsTag `json:"Tags"`
		} `json:"Volumes"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse aws volumes: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, v := range result.Volumes {
		rate, ok := awsEBSRatePerGBMonth[v.VolumeType]
		if !ok {
			rate = awsEBSRateDefault
		}
		tags := awsTagsToMap(v.Tags)
		res = append(res, adapter.ResourceInfo{
			ResourceID: v.VolumeId,
			Provider:   string(ProviderAWS),
			Kind:       adapter.ResourceDisk,
			Region:     region,
			RunID:      tags["dispatcher-run-id"],
			Tags:       tags,
			MonthlyUSD: float64(v.Size) * rate,
		})
	}
	return res, nil
}

func (a *AWSProvider) listSnapshotResources(ctx context.Context, region string) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-snapshots", "--owner-ids", "self", "--region", region, "--output", "json")
	if err != nil {
		return nil, err
	}
	var result struct {
		Snapshots []struct {
			SnapshotId string   `json:"SnapshotId"`
			VolumeSize int      `json:"VolumeSize"`
			Tags       []awsTag `json:"Tags"`
		} `json:"Snapshots"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse aws snapshots: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, s := range result.Snapshots {
		tags := awsTagsToMap(s.Tags)
		res = append(res, adapter.ResourceInfo{
			ResourceID: s.SnapshotId,
			Provider:   string(ProviderAWS),
			Kind:       adapter.ResourceSnapshot,
			Region:     region,
			RunID:      tags["dispatcher-run-id"],
			Tags:       tags,
			MonthlyUSD: float64(s.VolumeSize) * awsSnapshotRatePerGBMonth,
		})
	}
	return res, nil
}

func (a *AWSProvider) listAddressResources(ctx context.Context, region string) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-addresses", "--region", region, "--output", "json")
	if err != nil {
		return nil, err
	}
	var result struct {
		Addresses []struct {
			AllocationId  string   `json:"AllocationId"`
			AssociationId string   `json:"AssociationId"`
			Tags          []awsTag `json:"Tags"`
		} `json:"Addresses"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse aws addresses: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, ad := range result.Addresses {
		// An associated EIP is billed against its running instance; only an
		// unassociated one wastes money on its own.
		monthly := 0.0
		if ad.AssociationId == "" {
			monthly = awsEIPMonthlyUnassociated
		}
		tags := awsTagsToMap(ad.Tags)
		res = append(res, adapter.ResourceInfo{
			ResourceID: ad.AllocationId,
			Provider:   string(ProviderAWS),
			Kind:       adapter.ResourceAddress,
			Region:     region,
			RunID:      tags["dispatcher-run-id"],
			Tags:       tags,
			MonthlyUSD: monthly,
		})
	}
	return res, nil
}

// listSecurityGroupResources lists only dispatcher-tagged groups: SGs are free,
// so listing every group in the account would be pure noise. The value here is
// reaping a per-run SG that leaked when teardown's best-effort delete failed.
func (a *AWSProvider) listSecurityGroupResources(ctx context.Context, region string) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-security-groups", "--region", region,
		"--filters", "Name=tag:dispatcher,Values=true", "--output", "json")
	if err != nil {
		return nil, err
	}
	var result struct {
		SecurityGroups []struct {
			GroupId string   `json:"GroupId"`
			Tags    []awsTag `json:"Tags"`
		} `json:"SecurityGroups"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse aws security groups: %w", err)
	}
	var res []adapter.ResourceInfo
	for _, sg := range result.SecurityGroups {
		tags := awsTagsToMap(sg.Tags)
		res = append(res, adapter.ResourceInfo{
			ResourceID: sg.GroupId,
			Provider:   string(ProviderAWS),
			Kind:       adapter.ResourceFirewall,
			Region:     region,
			RunID:      tags["dispatcher-run-id"],
			Tags:       tags,
		})
	}
	return res, nil
}
