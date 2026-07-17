package cloudvm

import (
	"context"
	"strconv"
)

// azurePortOpener is an optional Provider capability: open the in-TEE agent's
// port on the VM's NSG. The rule is torn down with the VM's NSG at Cleanup, so
// there's no separate reap.
type azurePortOpener interface {
	OpenAgentPort(ctx context.Context, vmName string, port int, cidr string) error
}

// OpenAgentPort adds an inbound NSG rule permitting the agent port from cidr on
// the VM's auto-created NSG (<vmName>NSG). The endpoint is safe to expose
// (attestation + sealing); scoping to dispatcher's egress IP is defense in depth.
func (a *AzureProvider) OpenAgentPort(ctx context.Context, vmName string, port int, cidr string) error {
	if err := validateFirewallCIDR(cidr); err != nil {
		return err
	}
	_, err := runCLI(ctx, "az", "network", "nsg", "rule", "create",
		"--resource-group", a.resourceGroup,
		"--nsg-name", vmName+"NSG",
		"--name", "dispatcher-agent",
		"--priority", "1010",
		"--destination-port-ranges", strconv.Itoa(port),
		"--source-address-prefixes", cidr,
		"--access", "Allow", "--protocol", "Tcp", "--direction", "Inbound")
	return err
}

// confidentialAgentSSHOpts are the ssh/scp options for reaching a freshly-booted
// confidential VM to install the in-TEE agent, shared by the azure-snp and Nitro
// flows. Host key is accept-new (TOFU): the untrusted channel is made safe by
// attestation + sealing, not by SSH host identity.
func confidentialAgentSSHOpts(keyPath string) []string {
	return []string{"-i", keyPath, "-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=20"}
}
