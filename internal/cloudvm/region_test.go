package cloudvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSProvider_SetRegionAffectsTeardown(t *testing.T) {
	calls := captureRunCLI(t)
	aws := NewAWSProvider("") // defaults to us-east-1
	aws.SetRegion("eu-west-1")
	_ = aws.DestroyVM(context.Background(), "i-123")

	assert.True(t, containsCall(*calls, "aws", "ec2", "terminate-instances",
		"--region", "eu-west-1", "--instance-ids", "i-123"),
		"teardown must target the region the VM was created in, not the default")
}

func TestResolveUbuntuAMI_ArgvAndParse(t *testing.T) {
	calls := captureRunCLIWith(t, func(string, ...string) ([]byte, error) {
		return []byte("ami-0abc123def\n"), nil
	})
	ami, err := resolveUbuntuAMI(context.Background(), "ap-south-1", "x86_64")
	require.NoError(t, err)
	assert.Equal(t, "ami-0abc123def", ami, "the resolved AMI is trimmed")
	assert.True(t, containsCall(*calls, "aws", "ssm", "get-parameter",
		"--region", "ap-south-1", "--name", ubuntuAMISSMParam,
		"--query", "Parameter.Value", "--output", "text"),
		"AMI resolution queries SSM for the requested region")
}

func TestResolveUbuntuAMI_RejectsGarbage(t *testing.T) {
	captureRunCLIWith(t, func(string, ...string) ([]byte, error) {
		return []byte("None\n"), nil // SSM prints "None" when a parameter is missing
	})
	_, err := resolveUbuntuAMI(context.Background(), "us-east-1", "x86_64")
	require.Error(t, err, "a non-ami value must not be passed to run-instances")
}

// recordingRegionProvider is a MockProvider that also records SetRegion, to
// verify the adapter re-points its provider.
type recordingRegionProvider struct {
	*MockProvider
	region string
}

func (r *recordingRegionProvider) SetRegion(region string) { r.region = region }

func TestCloudVMAdapter_ReconnectRepointsRegion(t *testing.T) {
	rp := &recordingRegionProvider{MockProvider: NewMockProvider(ProviderAWS)}
	a := NewCloudVMAdapter(rp, Config{ProviderID: ProviderAWS})

	state := &CloudVMState{VMID: "i-1", Region: "eu-central-1"}
	raw, err := state.MarshalHandleState()
	require.NoError(t, err)

	_, err = a.Reconnect(context.Background(), "h1", raw)
	require.NoError(t, err)
	assert.Equal(t, "eu-central-1", rp.region,
		"reconnect re-points the provider to the VM's persisted region")
}
