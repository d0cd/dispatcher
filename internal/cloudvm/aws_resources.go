package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"

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

// ListResources enumerates billable AWS resources in the provider's region for
// the cost audit and GC: instances, EBS volumes, snapshots, Elastic IPs, and
// dispatcher-owned security groups. The instances list is reaping-critical and
// fails loud; auxiliary kinds are best-effort so a denied list can't blind gc to
// reapable instances. Resources in other regions are not visible (like ListVMs).
func (a *AWSProvider) ListResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := a.listInstanceResources(ctx)
	if err != nil {
		return nil, err
	}
	for _, step := range []func(context.Context) ([]adapter.ResourceInfo, error){
		a.listVolumeResources, a.listSnapshotResources, a.listAddressResources, a.listSecurityGroupResources,
	} {
		if rs, err := step(ctx); err == nil {
			out = append(out, rs...)
		}
	}
	return out, nil
}

// DestroyResource deletes a single AWS resource by kind. Callers (the adapter)
// enforce the dispatcher-owned boundary before reaching here.
func (a *AWSProvider) DestroyResource(ctx context.Context, res adapter.ResourceInfo) error {
	region := res.Region
	if region == "" {
		region = a.defaultRegion
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

func (a *AWSProvider) listInstanceResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-instances", "--region", a.defaultRegion, "--output", "json")
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
			res = append(res, adapter.ResourceInfo{
				ResourceID:   in.InstanceId,
				Provider:     string(ProviderAWS),
				Kind:         adapter.ResourceInstance,
				Region:       a.defaultRegion,
				InstanceType: in.InstanceType,
				RunID:        tags["dispatcher-run-id"],
				Tags:         tags,
				MonthlyUSD:   catalog.PriceByName(ProviderAWS, in.InstanceType) * gcpMonthlyHours,
			})
		}
	}
	return res, nil
}

func (a *AWSProvider) listVolumeResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-volumes", "--region", a.defaultRegion, "--output", "json")
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
			Region:     a.defaultRegion,
			RunID:      tags["dispatcher-run-id"],
			Tags:       tags,
			MonthlyUSD: float64(v.Size) * rate,
		})
	}
	return res, nil
}

func (a *AWSProvider) listSnapshotResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-snapshots", "--owner-ids", "self", "--region", a.defaultRegion, "--output", "json")
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
			Region:     a.defaultRegion,
			RunID:      tags["dispatcher-run-id"],
			Tags:       tags,
			MonthlyUSD: float64(s.VolumeSize) * awsSnapshotRatePerGBMonth,
		})
	}
	return res, nil
}

func (a *AWSProvider) listAddressResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-addresses", "--region", a.defaultRegion, "--output", "json")
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
			Region:     a.defaultRegion,
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
func (a *AWSProvider) listSecurityGroupResources(ctx context.Context) ([]adapter.ResourceInfo, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-security-groups", "--region", a.defaultRegion,
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
			Region:     a.defaultRegion,
			RunID:      tags["dispatcher-run-id"],
			Tags:       tags,
		})
	}
	return res, nil
}
