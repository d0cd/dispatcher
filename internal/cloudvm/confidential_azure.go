package cloudvm

import (
	"context"
	"crypto"
	"fmt"
	"strconv"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/types"
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
// confidential VM to install the in-TEE agent, shared by the Azure, AWS SEV-SNP,
// and Nitro flows. Host key is accept-new (TOFU): the untrusted channel is made
// safe by attestation + sealing, not by SSH host identity.
func confidentialAgentSSHOpts(keyPath string) []string {
	return []string{"-i", keyPath, "-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=20"}
}

// AzureConfidentialAdapter runs a workload on an Azure SEV-SNP confidential VM,
// attested via MAA and sealed (R9). Like the SSH-VM model it provisions a full
// VM, but the workload arrives sealed and runs inside the TEE via the agent's
// sealed exchange — not rsync-in-the-clear.
type AzureConfidentialAdapter struct {
	confidentialVMAdapter
	keys         map[string]crypto.PublicKey
	issuer       string
	maaURL       string
	agentBin     string
	measuredBoot attest.MAAMeasuredBoot
}

// NewAzureConfidentialAdapter builds the adapter. keys/issuer are the pinned MAA
// instance's signing keys and issuer; agentBin is the cross-compiled
// dispatcher-attest-azure binary dispatcher scps onto the CVM. mb optionally pins
// measured-boot PCRs (a custom measured image); its zero value keeps the
// firmware-only attestation (the scp'd agent is not measured).
func NewAzureConfidentialAdapter(provider Provider, keys map[string]crypto.PublicKey, issuer, maaURL, agentBin string, mb attest.MAAMeasuredBoot, cfg Config) *AzureConfidentialAdapter {
	return &AzureConfidentialAdapter{
		confidentialVMAdapter: confidentialVMAdapter{
			targetID: string(cfg.ProviderID) + "-confidential",
			provider: provider, config: cfg,
			costAssumption: "confidential (SEV-SNP) CVM",
		},
		keys: keys, issuer: issuer, maaURL: maaURL, agentBin: agentBin, measuredBoot: mb,
	}
}

func (a *AzureConfidentialAdapter) Execute(context.Context, *types.Plan) (*adapter.RunHandle, error) {
	return nil, fmt.Errorf("standard Azure MAA execution is disabled: its post-boot agent is not measured; use confidential.profile: azure-snp")
}
