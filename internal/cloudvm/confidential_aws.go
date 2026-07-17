package cloudvm

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// OpenAgentPort authorizes the agent port on the instance's security group from
// cidr. The SG is per-run and reaped with the instance, so there's no separate
// rule cleanup.
func (a *AWSProvider) OpenAgentPort(ctx context.Context, vmID string, port int, cidr string) error {
	if err := validateFirewallCIDR(cidr); err != nil {
		return err
	}
	out, err := runCLI(ctx, "aws", "ec2", "describe-instances",
		"--region", a.defaultRegion, "--instance-ids", vmID,
		"--query", "Reservations[0].Instances[0].SecurityGroups[0].GroupId", "--output", "text")
	if err != nil {
		return fmt.Errorf("find instance security group: %w", err)
	}
	sg := strings.TrimSpace(string(out))
	if sg == "" || sg == "None" {
		return fmt.Errorf("no security group on instance %s", vmID)
	}
	_, err = runCLI(ctx, "aws", "ec2", "authorize-security-group-ingress",
		"--region", a.defaultRegion, "--group-id", sg,
		"--protocol", "tcp", "--port", strconv.Itoa(port), "--cidr", cidr)
	return err
}

// awsPortOpener is the optional Provider capability the AWS start-agent uses.
type awsPortOpener interface {
	OpenAgentPort(ctx context.Context, vmID string, port int, cidr string) error
}
