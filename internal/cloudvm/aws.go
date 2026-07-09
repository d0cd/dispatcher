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

// AWSProvider implements Provider using the aws CLI.
type AWSProvider struct {
	defaultRegion string
}

// NewAWSProvider creates an AWS provider.
func NewAWSProvider(region string) *AWSProvider {
	if region == "" {
		region = "us-east-1"
	}
	return &AWSProvider{defaultRegion: region}
}

func (a *AWSProvider) Name() ProviderID { return ProviderAWS }

// SetRegion re-points the provider so create AND teardown act on the same
// region — DestroyVM/GetVM key off defaultRegion, so a run in a non-default
// region would otherwise leak (terminate would query the wrong region).
func (a *AWSProvider) SetRegion(region string) {
	if region != "" {
		a.defaultRegion = region
	}
}

// ubuntuAMISSMParam is Canonical's public SSM parameter for the current Ubuntu
// 22.04 amd64 image. It resolves to the correct AMI id per region, so we never
// hardcode a region-pinned AMI.
const ubuntuAMISSMParam = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"

// resolveUbuntuAMI looks up the region-correct Ubuntu AMI via SSM. AMI ids are
// region-scoped, so a fixed id only works in one region; this makes any region
// launchable without a hand-maintained region→AMI map.
func resolveUbuntuAMI(ctx context.Context, region string) (string, error) {
	var out []byte
	err := Retry(ctx, DefaultRetry, IsTransient, func() error {
		o, e := runCLI(ctx, "aws", "ssm", "get-parameter",
			"--region", region,
			"--name", ubuntuAMISSMParam,
			"--query", "Parameter.Value",
			"--output", "text",
		)
		if e != nil {
			return wrapExecError("aws ssm get-parameter", e)
		}
		out = o
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("resolve ubuntu AMI for region %s via SSM: %w", region, err)
	}
	ami := strings.TrimSpace(string(out))
	if !strings.HasPrefix(ami, "ami-") {
		return "", fmt.Errorf("SSM returned an unexpected AMI value %q for region %s", ami, region)
	}
	return ami, nil
}

func (a *AWSProvider) CheckCLI(ctx context.Context) error {
	if _, err := exec.LookPath("aws"); err != nil {
		return fmt.Errorf("aws CLI not found: %w", err)
	}
	cmd := exec.CommandContext(ctx, "aws", "sts", "get-caller-identity")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("aws not authenticated: %w", err)
	}
	return nil
}

// awsConfidentialArgs returns the run-instances flags for a confidential VM (or
// nil for non-confidential). AWS confidential VMs are AMD SEV-SNP only (no SEV,
// no TDX), on specific M6a/R6a/C6a types — the catalog must pick a compatible one.
func awsConfidentialArgs(opts VMOptions) ([]string, error) {
	if opts.ConfidentialType == "" {
		return nil, nil
	}
	if opts.ConfidentialType != "sev-snp" && opts.ConfidentialType != "any" {
		return nil, fmt.Errorf("aws supports only sev-snp confidential VMs, not %q", opts.ConfidentialType)
	}
	return []string{"--cpu-options", "AmdSevSnp=enabled"}, nil
}

func (a *AWSProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	region := opts.Region
	if region == "" {
		region = a.defaultRegion
	}
	// Validate tags before any CLI call (incl. the AMI lookup) so a crafted
	// value is rejected pre-exec. AWS joins tag KV pairs with commas inside the
	// --tag-specifications value, so a comma or `}` in a value would corrupt it.
	if err := validateLabels(opts.Tags); err != nil {
		return nil, fmt.Errorf("aws tags: %w", err)
	}
	// Reject an unsupported confidential type pre-exec, before the AMI lookup.
	confArgs, err := awsConfidentialArgs(opts)
	if err != nil {
		return nil, err
	}

	image := opts.Image
	if image == "" {
		resolved, err := resolveUbuntuAMI(ctx, region)
		if err != nil {
			return nil, fmt.Errorf("aws: %w", err)
		}
		image = resolved
	}
	instanceType := opts.InstanceType
	if instanceType == "" {
		instanceType = "t3.micro"
	}
	if err := validateVMArgs(region, instanceType, image); err != nil {
		return nil, fmt.Errorf("aws: %w", err)
	}

	// The default VPC security group only permits intra-group traffic, so
	// dispatcher would never reach the VM over SSH. Create a per-run group that
	// admits SSH (from AllowSSHFrom, or anywhere — key-only auth, matching GCP's
	// default posture) and delete it on teardown.
	sshCIDR := opts.AllowSSHFrom
	if sshCIDR == "" {
		sshCIDR = "0.0.0.0/0"
	}
	sgID, err := awsCreateSSHSecurityGroup(ctx, region, awsSGName(opts), sshCIDR)
	if err != nil {
		return nil, err
	}

	var tagSpecs []string
	for k, v := range opts.Tags {
		tagSpecs = append(tagSpecs, fmt.Sprintf("{Key=%s,Value=%s}", k, v))
	}
	tagSpec := fmt.Sprintf("ResourceType=instance,Tags=[%s]", strings.Join(tagSpecs, ","))

	args := []string{
		"ec2", "run-instances",
		"--region", region,
		"--image-id", image,
		"--instance-type", instanceType,
		"--count", "1",
		"--security-group-ids", sgID,
		"--tag-specifications", tagSpec,
		"--output", "json",
	}

	args = append(args, confArgs...)

	// AWS has no metadata SSH channel like GCP, so dispatcher's per-run key is
	// folded into the boot user-data (installed into the login user's
	// authorized_keys). Without it the instance authorizes no key and SSH fails.
	userData := opts.UserData
	if opts.SSHKeyPath != "" && opts.SSHUser != "" {
		pub, err := os.ReadFile(opts.SSHKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read ssh pubkey: %w", err)
		}
		userData = awsUserDataWithSSHKey(userData, opts.SSHUser, string(pub))
	}
	if userData != "" {
		// Pass user-data via `file://` so it never appears in argv (visible
		// to other users on the host via `ps`).
		f, err := adapter.WriteSecureTempFile("dispatcher-aws-userdata-*.yaml", []byte(userData))
		if err != nil {
			return nil, fmt.Errorf("write user-data: %w", err)
		}
		defer os.Remove(f)
		args = append(args, "--user-data", "file://"+f)
	}

	output, err := retryCLIOutput(ctx, "aws", "aws ec2 run-instances", args...)
	if err != nil {
		// No instance took ownership of the group; reclaim it now.
		awsDeleteSecurityGroup(ctx, region, sgID)
		return nil, err
	}

	var result struct {
		Instances []struct {
			InstanceId string `json:"InstanceId"`
		} `json:"Instances"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("cannot parse aws output: %w", err)
	}

	if len(result.Instances) == 0 {
		return nil, fmt.Errorf("no instances created")
	}

	instanceID := result.Instances[0].InstanceId

	// Wait for public IP
	ip, err := a.waitForIP(ctx, instanceID, region)
	if err != nil {
		_ = a.DestroyVM(ctx, instanceID)
		return nil, err
	}

	return &VMInfo{
		ID:        instanceID,
		IP:        ip,
		State:     VMStateRunning,
		CreatedAt: time.Now().UTC(),
		Tags:      opts.Tags,
	}, nil
}

// awsUserDataWithSSHKey appends a boot-script snippet that installs pubKey into
// sshUser's authorized_keys. AWS has no ssh-keys metadata channel like GCP, and
// this needs no teardown — the key dies with the instance. A base user-data
// (the watchdog) supplies the shebang; if absent we add one.
func awsUserDataWithSSHKey(userData, sshUser, pubKey string) string {
	if userData == "" {
		userData = "#!/bin/sh\n"
	}
	home := "/home/" + sshUser
	key := adapter.ShellQuote(strings.TrimSpace(pubKey))
	snippet := fmt.Sprintf(`
mkdir -p %[1]s/.ssh
echo %[2]s >> %[1]s/.ssh/authorized_keys
chown -R %[3]s:%[3]s %[1]s/.ssh
chmod 700 %[1]s/.ssh
chmod 600 %[1]s/.ssh/authorized_keys
`, home, key, sshUser)
	return userData + snippet
}

// awsSGName is the per-run security group name (unique per run id).
func awsSGName(opts VMOptions) string {
	id := opts.Tags["dispatcher-run-id"]
	if id == "" {
		id = opts.Name
	}
	return "dispatcher-" + adapter.SanitizeName(id)
}

// awsCreateSSHSecurityGroup creates a security group in the region's default VPC
// admitting inbound SSH from cidr, and returns its group id. The group is
// deleted on teardown (or if run-instances fails).
func awsCreateSSHSecurityGroup(ctx context.Context, region, name, cidr string) (string, error) {
	out, err := runCLI(ctx, "aws", "ec2", "describe-vpcs", "--region", region,
		"--filters", "Name=isDefault,Values=true", "--query", "Vpcs[0].VpcId", "--output", "text")
	if err != nil {
		return "", fmt.Errorf("aws describe default vpc: %w", err)
	}
	vpc := strings.TrimSpace(string(out))
	if vpc == "" || vpc == "None" {
		return "", fmt.Errorf("no default VPC in %s to place the SSH security group", region)
	}
	out, err = runCLI(ctx, "aws", "ec2", "create-security-group", "--region", region,
		"--group-name", name, "--description", "dispatcher per-run SSH access",
		"--vpc-id", vpc, "--query", "GroupId", "--output", "text")
	if err != nil {
		return "", fmt.Errorf("aws create security group: %w", err)
	}
	sg := strings.TrimSpace(string(out))
	if _, err := runCLI(ctx, "aws", "ec2", "authorize-security-group-ingress", "--region", region,
		"--group-id", sg, "--protocol", "tcp", "--port", "22", "--cidr", cidr); err != nil {
		awsDeleteSecurityGroup(ctx, region, sg)
		return "", fmt.Errorf("aws authorize ssh ingress: %w", err)
	}
	return sg, nil
}

// awsDeleteSecurityGroup removes a group (best-effort; a group in use can't be
// deleted until its instance is gone, so callers that just terminated retry).
func awsDeleteSecurityGroup(ctx context.Context, region, sgID string) {
	_, _ = runCLI(ctx, "aws", "ec2", "delete-security-group", "--region", region, "--group-id", sgID)
}

// awsInstanceDispatcherSGs returns the dispatcher-created security group ids
// attached to an instance (best-effort).
func awsInstanceDispatcherSGs(ctx context.Context, region, vmID string) []string {
	out, err := runCLI(ctx, "aws", "ec2", "describe-instances", "--region", region,
		"--instance-ids", vmID,
		"--query", "Reservations[].Instances[].SecurityGroups[?starts_with(GroupName, `dispatcher-`)].GroupId",
		"--output", "text")
	if err != nil {
		return nil
	}
	var ids []string
	for _, f := range strings.Fields(string(out)) {
		if f != "" && f != "None" {
			ids = append(ids, f)
		}
	}
	return ids
}

func (a *AWSProvider) waitForIP(ctx context.Context, instanceID, region string) (string, error) {
	deadline := time.After(3 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline:
			return "", fmt.Errorf("timeout waiting for public IP")
		case <-ticker.C:
			vm, err := a.getVMInRegion(ctx, instanceID, region)
			if err == nil && vm.IP != "" {
				return vm.IP, nil
			}
		}
	}
}

func (a *AWSProvider) WaitReady(ctx context.Context, _ string, ip string, _ string) error {
	return WaitForSSH(ctx, ip, 5*time.Minute)
}

func (a *AWSProvider) GetVM(ctx context.Context, vmID string) (*VMInfo, error) {
	return a.getVMInRegion(ctx, vmID, a.defaultRegion)
}

func (a *AWSProvider) getVMInRegion(ctx context.Context, vmID, region string) (*VMInfo, error) {
	output, err := runCLI(ctx, "aws", "ec2", "describe-instances",
		"--region", region,
		"--instance-ids", vmID,
		"--output", "json",
	)
	if err != nil {
		return nil, wrapExecError("aws ec2 describe-instances", err)
	}

	var result struct {
		Reservations []struct {
			Instances []struct {
				InstanceId      string `json:"InstanceId"`
				PublicIpAddress string `json:"PublicIpAddress"`
				State           struct {
					Name string `json:"Name"`
				} `json:"State"`
			} `json:"Instances"`
		} `json:"Reservations"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}
	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
	}

	inst := result.Reservations[0].Instances[0]
	state := VMStateRunning
	if inst.State.Name == "terminated" || inst.State.Name == "shutting-down" {
		state = VMStateTerminated
	}

	return &VMInfo{
		ID:    inst.InstanceId,
		IP:    inst.PublicIpAddress,
		State: state,
	}, nil
}

func (a *AWSProvider) DestroyVM(ctx context.Context, vmID string) error {
	// Capture the per-run security group before terminating; it can only be
	// deleted once the instance releases it.
	sgs := awsInstanceDispatcherSGs(ctx, a.defaultRegion, vmID)
	if _, err := runCLI(ctx, "aws", "ec2", "terminate-instances",
		"--region", a.defaultRegion,
		"--instance-ids", vmID,
	); err != nil {
		return fmt.Errorf("aws ec2 terminate-instances failed: %w", err)
	}
	for _, sg := range sgs {
		a.deleteSGWhenReleased(ctx, sg)
	}
	return nil
}

// deleteSGWhenReleased retries deleting a security group until the terminating
// instance releases it (DependencyViolation clears once terminated). Bounded so
// teardown can't hang.
func (a *AWSProvider) deleteSGWhenReleased(ctx context.Context, sgID string) {
	for i := 0; i < 18; i++ {
		if _, err := runCLI(ctx, "aws", "ec2", "delete-security-group",
			"--region", a.defaultRegion, "--group-id", sgID); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func (a *AWSProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	if err := validateLabels(tags); err != nil {
		return nil, fmt.Errorf("aws filter tags: %w", err)
	}
	args := []string{"ec2", "describe-instances",
		"--region", a.defaultRegion,
		"--output", "json",
	}

	var filters []string
	for k, v := range tags {
		filters = append(filters, fmt.Sprintf("Name=tag:%s,Values=%s", k, v))
	}
	if len(filters) > 0 {
		args = append(args, "--filters")
		args = append(args, filters...)
	}

	output, err := runCLI(ctx, "aws", args...)
	if err != nil {
		return nil, wrapExecError("aws ec2 describe-instances", err)
	}

	var result struct {
		Reservations []struct {
			Instances []struct {
				InstanceId string `json:"InstanceId"`
				State      struct {
					Name string `json:"Name"`
				} `json:"State"`
				Tags []struct {
					Key   string `json:"Key"`
					Value string `json:"Value"`
				} `json:"Tags"`
			} `json:"Instances"`
		} `json:"Reservations"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	var vms []VMInfo
	for _, res := range result.Reservations {
		for _, inst := range res.Instances {
			if inst.State.Name == "terminated" {
				continue
			}
			vmTags := make(map[string]string)
			for _, t := range inst.Tags {
				vmTags[t.Key] = t.Value
			}
			vms = append(vms, VMInfo{
				ID:    inst.InstanceId,
				State: VMState(inst.State.Name),
				Tags:  vmTags,
			})
		}
	}
	return vms, nil
}
