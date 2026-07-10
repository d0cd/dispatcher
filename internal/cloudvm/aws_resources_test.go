package cloudvm

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// awsListResponses drives the runCLI seam with a canned JSON body per
// `aws ec2 describe-<kind>` call, keyed by the describe verb in argv[1].
func awsListResponses(bodies map[string]string) func(string, ...string) ([]byte, error) {
	return func(_ string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "ec2" {
			if body, ok := bodies[args[1]]; ok {
				return []byte(body), nil
			}
		}
		return []byte("{}"), nil
	}
}

func TestAWSProvider_ListResources_Argv(t *testing.T) {
	calls := captureRunCLIWith(t, awsListResponses(nil))
	p := NewAWSProvider("us-west-2")

	_, err := p.ListResources(context.Background())
	require.NoError(t, err)

	assert.True(t, containsCall(*calls, "aws", "ec2", "describe-instances", "--region", "us-west-2", "--output", "json"))
	assert.True(t, containsCall(*calls, "aws", "ec2", "describe-volumes", "--region", "us-west-2", "--output", "json"))
	assert.True(t, containsCall(*calls, "aws", "ec2", "describe-snapshots", "--owner-ids", "self", "--region", "us-west-2", "--output", "json"))
	assert.True(t, containsCall(*calls, "aws", "ec2", "describe-addresses", "--region", "us-west-2", "--output", "json"))
	assert.True(t, containsCall(*calls, "aws", "ec2", "describe-security-groups", "--region", "us-west-2", "--filters", "Name=tag:dispatcher,Values=true", "--output", "json"))
}

func TestAWSProvider_ListResources_ParsesAndCosts(t *testing.T) {
	bodies := map[string]string{
		"describe-instances": `{"Reservations":[{"Instances":[{
			"InstanceId":"i-1","InstanceType":"t3.micro","State":{"Name":"running"},
			"Tags":[{"Key":"dispatcher","Value":"true"},{"Key":"dispatcher-run-id","Value":"run_9"}]}]}]}`,
		"describe-volumes": `{"Volumes":[{
			"VolumeId":"vol-1","Size":100,"VolumeType":"gp3","State":"available",
			"Tags":[{"Key":"owner","Value":"other"}]}]}`,
		"describe-snapshots": `{"Snapshots":[{
			"SnapshotId":"snap-1","VolumeSize":50,"Tags":[{"Key":"dispatcher","Value":"true"}]}]}`,
		"describe-addresses": `{"Addresses":[{
			"AllocationId":"eipalloc-1","PublicIp":"1.2.3.4","Tags":[]}]}`,
		"describe-security-groups": `{"SecurityGroups":[{
			"GroupId":"sg-1","GroupName":"dispatcher-run_9",
			"Tags":[{"Key":"dispatcher","Value":"true"},{"Key":"dispatcher-run-id","Value":"run_9"}]}]}`,
	}
	captureRunCLIWith(t, awsListResponses(bodies))
	p := NewAWSProvider("us-east-1")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err)

	byID := map[string]adapter.ResourceInfo{}
	for _, r := range res {
		byID[r.ResourceID] = r
	}

	inst := byID["i-1"]
	assert.Equal(t, adapter.ResourceInstance, inst.Kind)
	assert.Equal(t, "us-east-1", inst.Region)
	assert.Equal(t, "t3.micro", inst.InstanceType)
	assert.Equal(t, "run_9", inst.RunID)
	assert.True(t, inst.DispatcherOwned())
	assert.InDelta(t, 0.0104*gcpMonthlyHours, inst.MonthlyUSD, 0.5)

	vol := byID["vol-1"]
	assert.Equal(t, adapter.ResourceDisk, vol.Kind)
	assert.False(t, vol.DispatcherOwned(), "untagged volume -> external")
	assert.InDelta(t, 100*0.08, vol.MonthlyUSD, 0.01) // gp3

	snap := byID["snap-1"]
	assert.Equal(t, adapter.ResourceSnapshot, snap.Kind)
	assert.InDelta(t, 50*0.05, snap.MonthlyUSD, 0.01)

	eip := byID["eipalloc-1"]
	assert.Equal(t, adapter.ResourceAddress, eip.Kind)
	assert.Greater(t, eip.MonthlyUSD, 0.0, "an unassociated EIP bills")

	sg := byID["sg-1"]
	assert.Equal(t, adapter.ResourceFirewall, sg.Kind)
	assert.Equal(t, "run_9", sg.RunID)
	assert.True(t, sg.DispatcherOwned())
	assert.Equal(t, 0.0, sg.MonthlyUSD, "security groups are free")
}

func TestAWSProvider_ListResources_SkipsTerminatedAndAssociatedEIP(t *testing.T) {
	bodies := map[string]string{
		"describe-instances": `{"Reservations":[{"Instances":[{"InstanceId":"i-dead","InstanceType":"t3.micro","State":{"Name":"terminated"}}]}]}`,
		"describe-addresses": `{"Addresses":[{"AllocationId":"eipalloc-live","PublicIp":"5.6.7.8","AssociationId":"eipassoc-1","Tags":[]}]}`,
	}
	captureRunCLIWith(t, awsListResponses(bodies))
	p := NewAWSProvider("us-east-1")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err)
	for _, r := range res {
		assert.NotEqual(t, "i-dead", r.ResourceID, "a terminated instance is not billable")
		if r.ResourceID == "eipalloc-live" {
			assert.Equal(t, 0.0, r.MonthlyUSD, "an associated EIP bills against its instance, not on its own")
		}
	}
}

func TestAWSProvider_ListResources_AuxKindErrorIsNonFatal(t *testing.T) {
	resp := func(_ string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[1] == "describe-volumes" {
			return nil, assert.AnError
		}
		if len(args) >= 2 && args[1] == "describe-instances" {
			return []byte(`{"Reservations":[{"Instances":[{"InstanceId":"i-1","InstanceType":"t3.micro","State":{"Name":"running"},"Tags":[{"Key":"dispatcher","Value":"true"}]}]}]}`), nil
		}
		return []byte("{}"), nil
	}
	captureRunCLIWith(t, resp)
	p := NewAWSProvider("us-east-1")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err, "an auxiliary kind's error must not fail the whole enumeration")
	require.Len(t, res, 1)
	assert.Equal(t, "i-1", res[0].ResourceID)
}

// gc must see orphans in every enabled region, not just the provider's default
// — a run can be provisioned in another region, and its leaked instance would
// otherwise bill forever, invisible to the audit.
func TestAWSProvider_ListResources_SweepsAllRegions(t *testing.T) {
	resp := func(_ string, args ...string) ([]byte, error) {
		region := ""
		for i, a := range args {
			if a == "--region" && i+1 < len(args) {
				region = args[i+1]
			}
		}
		switch {
		case len(args) >= 2 && args[1] == "describe-regions":
			return []byte(`["us-east-1","eu-west-1"]`), nil
		case len(args) >= 2 && args[1] == "describe-instances":
			return []byte(`{"Reservations":[{"Instances":[{"InstanceId":"i-` + region +
				`","InstanceType":"t3.micro","State":{"Name":"running"},"Tags":[{"Key":"dispatcher","Value":"true"}]}]}]}`), nil
		}
		return []byte("{}"), nil
	}
	captureRunCLIWith(t, resp)
	p := NewAWSProvider("us-east-1")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err)

	byID := map[string]adapter.ResourceInfo{}
	for _, r := range res {
		byID[r.ResourceID] = r
	}
	require.Contains(t, byID, "i-us-east-1")
	require.Contains(t, byID, "i-eu-west-1")
	assert.Equal(t, "us-east-1", byID["i-us-east-1"].Region)
	assert.Equal(t, "eu-west-1", byID["i-eu-west-1"].Region,
		"a resource must carry the region it was found in, so DestroyResource targets it")
}

func TestAWSProvider_DestroyResource_Argv(t *testing.T) {
	p := NewAWSProvider("us-east-1")

	cases := []struct {
		name string
		res  adapter.ResourceInfo
		want []string
	}{
		{"instance",
			adapter.ResourceInfo{ResourceID: "i-1", Kind: adapter.ResourceInstance, Region: "us-east-1"},
			[]string{"ec2", "terminate-instances", "--region", "us-east-1", "--instance-ids", "i-1"}},
		{"volume",
			adapter.ResourceInfo{ResourceID: "vol-1", Kind: adapter.ResourceDisk, Region: "us-east-1"},
			[]string{"ec2", "delete-volume", "--region", "us-east-1", "--volume-id", "vol-1"}},
		{"snapshot",
			adapter.ResourceInfo{ResourceID: "snap-1", Kind: adapter.ResourceSnapshot, Region: "us-east-1"},
			[]string{"ec2", "delete-snapshot", "--region", "us-east-1", "--snapshot-id", "snap-1"}},
		{"address",
			adapter.ResourceInfo{ResourceID: "eipalloc-1", Kind: adapter.ResourceAddress, Region: "us-east-1"},
			[]string{"ec2", "release-address", "--region", "us-east-1", "--allocation-id", "eipalloc-1"}},
		{"firewall",
			adapter.ResourceInfo{ResourceID: "sg-1", Kind: adapter.ResourceFirewall, Region: "us-east-1"},
			[]string{"ec2", "delete-security-group", "--region", "us-east-1", "--group-id", "sg-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := captureRunCLI(t)
			_ = p.DestroyResource(context.Background(), tc.res)
			got := lastCall(t, calls)
			assert.Equal(t, "aws", got.name)
			assert.Equal(t, tc.want, got.args)
		})
	}
}

// A per-run security group must be tagged dispatcher=true (and with the run id)
// at creation, so gc can recognize it as dispatcher-owned and reap a leaked one.
func TestAWSCreateSecurityGroup_TagsDispatcherOwned(t *testing.T) {
	calls := captureRunCLIWith(t, func(_ string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[1] == "describe-vpcs" {
			return []byte("vpc-123\n"), nil
		}
		if len(args) >= 2 && args[1] == "create-security-group" {
			return []byte("sg-123\n"), nil
		}
		return []byte(""), nil
	})

	_, err := awsCreateSSHSecurityGroup(context.Background(), "us-east-1", "dispatcher-run_9", "0.0.0.0/0",
		map[string]string{"dispatcher": "true", "dispatcher-run-id": "run_9"})
	require.NoError(t, err)

	var found bool
	for _, c := range *calls {
		if len(c.args) >= 2 && c.args[1] == "create-security-group" {
			joined := strings.Join(c.args, " ")
			assert.Contains(t, joined, "--tag-specifications")
			assert.Contains(t, joined, "ResourceType=security-group")
			assert.Contains(t, joined, "Key=dispatcher,Value=true")
			found = true
		}
	}
	assert.True(t, found, "create-security-group must be issued")
}
