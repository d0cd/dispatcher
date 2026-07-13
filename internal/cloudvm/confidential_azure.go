package cloudvm

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/types"
)

// azureDeps are the Azure confidential run's collaborators. The live operations
// (provision, start the agent on the CVM, endpoint reachability) are seams so the
// orchestration — the verify-before-seal ordering — is unit-testable without a
// cloud or a TEE.
type azureDeps struct {
	provider  Provider
	keys      map[string]crypto.PublicKey // pinned MAA /certs keys
	issuer    string                      // pinned MAA instance issuer
	mb        attest.MAAMeasuredBoot      // optional measured-boot PCR pin (custom image)
	sshPubKey string                      // public key path to authorize on the CVM
	sshUser   string
	// startAgent provisions the agent on a booted CVM (scp the binary, start it,
	// open the NSG for its port) and returns its endpoint base URL.
	startAgent func(ctx context.Context, vm *VMInfo) (baseURL string, err error)
	waitReady  func(ctx context.Context, baseURL string) error
}

// executeAzureConfidential is the Azure orchestration: the shared SSH-VM
// confidential flow with MAA verification over the agent endpoint. The
// measurement allowlist comes from the workload's confidential.measurements
// (operator-pinned, since Azure's launch measurement is set by the CVM image).
func executeAzureConfidential(ctx context.Context, d azureDeps, p *types.Plan) (*confidentialRunState, error) {
	deps := sshConfidentialDeps{
		provider: d.provider, confidential: "sev-snp",
		sshPubKey: d.sshPubKey, sshUser: d.sshUser,
		startAgent: d.startAgent, waitReady: d.waitReady,
		verify: func(ctx context.Context, _ *VMInfo, baseURL string, req types.ConfidentialRequirement) (attest.AttestationResult, error) {
			return attest.NewAzureAttester(d.keys, d.issuer, baseURL, d.mb).Verify(ctx, req)
		},
	}
	return executeSSHConfidential(ctx, deps, p, fmt.Sprintf("dispatcher-cvm-%s", adapter.SanitizeName(p.Workload.Name)))
}

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

// azureStartAgent returns a startAgent that provisions the in-TEE agent on a
// booted CVM: wait for SSH, scp the agent binary, start it (root, for the vTPM),
// and open the NSG for its port.
//
// SECURITY NOTE: unlike GCP Confidential Space (where the container image digest
// IS the attested measurement, proving the agent), Azure's launch measurement
// covers the CVM/OS image, NOT this scp'd agent. So the guarantee currently
// assumes the SSH delivery channel and host don't substitute a different agent.
// Closing this needs the agent baked into a measured custom CVM image
// (docs/confidential-azure-maa.md).
func azureStartAgent(agentBin, maaURL, keyPath, sshUser, egressCIDR string, provider Provider) func(context.Context, *VMInfo) (string, error) {
	return func(ctx context.Context, vm *VMInfo) (string, error) {
		if err := provider.WaitReady(ctx, vm.ID, vm.IP, keyPath); err != nil {
			return "", fmt.Errorf("wait for ssh: %w", err)
		}
		opts := confidentialAgentSSHOpts(keyPath)
		target := sshUser + "@" + vm.IP

		scpArgs := append(append([]string{}, opts...), agentBin, target+":/tmp/dispatcher-agent")
		if out, err := exec.CommandContext(ctx, "scp", scpArgs...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("scp agent: %s: %w", strings.TrimSpace(string(out)), err)
		}

		// Defense in depth: maaURL is embedded in a guest-side `bash -c '...'`
		// literal. The CLI boundary validates it, but re-check here so no caller
		// can smuggle a shell-metacharacter-bearing URL past this point.
		if err := ValidateAgentURL(maaURL); err != nil {
			return "", fmt.Errorf("unsafe maa url: %w", err)
		}
		start := fmt.Sprintf("chmod +x /tmp/dispatcher-agent && sudo bash -c 'nohup /tmp/dispatcher-agent --addr=:%d --maa-url=%s >/tmp/dispatcher-agent.log 2>&1 &' && sleep 2",
			csAgentPort, maaURL)
		sshArgs := append(append([]string{}, opts...), target, start)
		if out, err := exec.CommandContext(ctx, "ssh", sshArgs...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("start agent: %s: %w", strings.TrimSpace(string(out)), err)
		}

		if op, ok := provider.(azurePortOpener); ok && egressCIDR != "" {
			if err := op.OpenAgentPort(ctx, vm.Name, csAgentPort, egressCIDR); err != nil {
				return "", fmt.Errorf("open agent port: %w", err)
			}
		}
		return fmt.Sprintf("http://%s:%d", vm.IP, csAgentPort), nil
	}
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

func (a *AzureConfidentialAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	if a.agentBin == "" {
		return nil, fmt.Errorf("azure confidential adapter has no agent binary configured")
	}
	a.resolveRegion(p)

	keyPath, err := generateSSHKey(ctx, p.Metadata.ID)
	if err != nil {
		return nil, fmt.Errorf("generate ssh key: %w", err)
	}
	defer func() {
		_ = os.Remove(keyPath)
		_ = os.Remove(keyPath + ".pub")
	}()

	egress, err := detectEgressCIDR(ctx)
	if err != nil {
		return nil, fmt.Errorf("scope confidential agent firewall: %w", err)
	}
	deps := azureDeps{
		provider:   a.provider,
		keys:       a.keys,
		issuer:     a.issuer,
		mb:         a.measuredBoot,
		sshPubKey:  keyPath + ".pub",
		sshUser:    a.config.SSHUser,
		startAgent: azureStartAgent(a.agentBin, a.maaURL, keyPath, a.config.SSHUser, egress, a.provider),
		waitReady:  waitForAgentEndpoint,
	}
	state, err := executeAzureConfidential(ctx, deps, p)
	if err != nil {
		return nil, err
	}
	return &adapter.RunHandle{ID: state.VMID, TargetID: a.targetID, State: state}, nil
}
