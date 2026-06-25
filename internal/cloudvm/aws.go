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
	defaultAMI    string
}

// NewAWSProvider creates an AWS provider.
func NewAWSProvider(region string) *AWSProvider {
	if region == "" {
		region = "us-east-1"
	}
	return &AWSProvider{
		defaultRegion: region,
		defaultAMI:    "ami-0c7217cdde317cfec", // Ubuntu 22.04 us-east-1
	}
}

func (a *AWSProvider) Name() ProviderID { return ProviderAWS }

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

func (a *AWSProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	region := opts.Region
	if region == "" {
		region = a.defaultRegion
	}
	image := opts.Image
	if image == "" {
		image = a.defaultAMI
	}
	instanceType := opts.InstanceType
	if instanceType == "" {
		instanceType = "t3.micro"
	}
	if err := validateVMArgs(region, instanceType, image); err != nil {
		return nil, fmt.Errorf("aws: %w", err)
	}
	if opts.AllowSSHFrom != "" {
		return nil, errFirewallUnsupported("aws")
	}

	// Build tag specifications. AWS uses commas to separate tag KV pairs
	// inside the --tag-specifications value, so a label value with a comma
	// or `}` would corrupt the spec. Validation at the boundary catches it.
	if err := validateLabels(opts.Tags); err != nil {
		return nil, fmt.Errorf("aws tags: %w", err)
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
		"--tag-specifications", tagSpec,
		"--output", "json",
	}

	if opts.ConfidentialType != "" {
		// AWS confidential VMs are AMD SEV-SNP only (no SEV, no TDX), on
		// specific M6a/R6a/C6a types — the catalog must pick a compatible one.
		if opts.ConfidentialType != "sev-snp" && opts.ConfidentialType != "any" {
			return nil, fmt.Errorf("aws supports only sev-snp confidential VMs, not %q", opts.ConfidentialType)
		}
		args = append(args, "--cpu-options", "AmdSevSnp=enabled")
	}

	if opts.UserData != "" {
		// Pass user-data via `file://` so it never appears in argv (visible
		// to other users on the host via `ps`). Today user-data is just the
		// watchdog cloud-init script; if we ever inject creds, this stops
		// being a "low" issue and prevents leakage upfront.
		f, err := adapter.WriteSecureTempFile("dispatcher-aws-userdata-*.yaml", []byte(opts.UserData))
		if err != nil {
			return nil, fmt.Errorf("write user-data: %w", err)
		}
		defer os.Remove(f)
		args = append(args, "--user-data", "file://"+f)
	}

	output, err := retryCLIOutput(ctx, "aws", "aws ec2 run-instances", args...)
	if err != nil {
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
	if _, err := runCLI(ctx, "aws", "ec2", "terminate-instances",
		"--region", a.defaultRegion,
		"--instance-ids", vmID,
	); err != nil {
		return fmt.Errorf("aws ec2 terminate-instances failed: %w", err)
	}
	return nil
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
