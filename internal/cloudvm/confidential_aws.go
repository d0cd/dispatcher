package cloudvm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/types"
)

// awsDeps are the AWS confidential run's collaborators (see sshConfidentialDeps).
type awsDeps struct {
	provider   Provider
	image      string
	sshPubKey  string
	sshUser    string
	startAgent func(ctx context.Context, vm *VMInfo) (string, error)
	waitReady  func(ctx context.Context, baseURL string) error
}

// executeAWSConfidential is the AWS orchestration: the shared SSH-VM flow with
// raw SEV-SNP verification (go-sev-guest + VLEK chain) over the agent endpoint.
func executeAWSConfidential(ctx context.Context, d awsDeps, p *types.Plan) (*confidentialRunState, error) {
	deps := sshConfidentialDeps{
		provider: d.provider, image: d.image, confidential: "sev-snp",
		sshPubKey: d.sshPubKey, sshUser: d.sshUser,
		startAgent: d.startAgent, waitReady: d.waitReady,
		verify: func(ctx context.Context, _ *VMInfo, baseURL string, req types.ConfidentialRequirement) (attest.AttestationResult, error) {
			return attest.NewAWSAttester(baseURL).Verify(ctx, req)
		},
	}
	return executeSSHConfidential(ctx, deps, p, fmt.Sprintf("dispatcher-snp-%s", adapter.SanitizeName(p.Workload.Name)))
}

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

// awsStartAgent returns a startAgent that provisions the in-TEE agent on a booted
// SEV-SNP instance: wait for SSH, scp the agent, start it (root, for
// /dev/sev-guest), and open the security group for its port.
//
// SECURITY NOTE: the scp'd agent is not part of the attested measurement. On
// EC2 the SEV-SNP launch measurement anchors the AWS-provided guest firmware —
// not the OS image or this agent — so a pinned measurement proves "genuine AWS
// SEV-SNP firmware", and freshness/binding come from REPORT_DATA. Unlike Azure
// (a vTPM measures the boot chain into MAA-attested PCRs), EC2 SEV-SNP has no
// vTPM/PCR chain, so the agent CANNOT be folded into the launch measurement via a
// custom AMI. Measuring the agent on AWS requires Nitro Enclaves, where the
// enclave image itself is measured (PCR0) — a separate execution model; its
// verifier is attest.NewAWSNitroAttester. Until then, agent integrity on this
// SEV-SNP path rests on the SSH delivery + host not tampering with the binary.
func awsStartAgent(agentBin, keyPath, sshUser, egressCIDR string, provider Provider) func(context.Context, *VMInfo) (string, error) {
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
		start := fmt.Sprintf("chmod +x /tmp/dispatcher-agent && sudo bash -c 'nohup /tmp/dispatcher-agent --addr=:%d >/tmp/dispatcher-agent.log 2>&1 &' && sleep 2", csAgentPort)
		sshArgs := append(append([]string{}, opts...), target, start)
		if out, err := exec.CommandContext(ctx, "ssh", sshArgs...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("start agent: %s: %w", strings.TrimSpace(string(out)), err)
		}
		if op, ok := provider.(awsPortOpener); ok && egressCIDR != "" {
			if err := op.OpenAgentPort(ctx, vm.ID, csAgentPort, egressCIDR); err != nil {
				return "", fmt.Errorf("open agent port: %w", err)
			}
		}
		return fmt.Sprintf("http://%s:%d", vm.IP, csAgentPort), nil
	}
}

// resolveAWSConfidentialAMI returns the SEV-SNP-capable Ubuntu 24.04 AMI (which
// exposes /dev/sev-guest) for the region — the operator override or SSM.
func resolveAWSConfidentialAMI(ctx context.Context, region string) (string, error) {
	if a := os.Getenv("DISPATCHER_AWS_AMI"); a != "" {
		return a, nil
	}
	out, err := runCLI(ctx, "aws", "ssm", "get-parameters", "--region", region,
		"--names", "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
		"--query", "Parameters[0].Value", "--output", "text")
	if err != nil {
		return "", fmt.Errorf("resolve 24.04 AMI: %w", err)
	}
	ami := strings.TrimSpace(string(out))
	if !strings.HasPrefix(ami, "ami-") {
		return "", fmt.Errorf("unexpected AMI %q", ami)
	}
	return ami, nil
}

// AWSConfidentialAdapter runs a workload on an AWS SEV-SNP VM, attested via a raw
// report (go-sev-guest + VLEK chain) and sealed (R9).
type AWSConfidentialAdapter struct {
	confidentialVMAdapter
	agentBin string
	region   string
}

// NewAWSConfidentialAdapter builds the adapter. agentBin is the cross-compiled
// dispatcher-attest-aws binary dispatcher scps onto the instance.
func NewAWSConfidentialAdapter(provider Provider, agentBin string, cfg Config) *AWSConfidentialAdapter {
	return &AWSConfidentialAdapter{
		confidentialVMAdapter: confidentialVMAdapter{
			targetID: string(cfg.ProviderID) + "-confidential",
			provider: provider, config: cfg,
			costAssumption: "confidential (SEV-SNP) VM",
		},
		agentBin: agentBin, region: cfg.Region,
	}
}

func (a *AWSConfidentialAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	if a.agentBin == "" {
		return nil, fmt.Errorf("aws confidential adapter has no agent binary configured")
	}
	region := a.resolveRegion(p)
	ami, err := resolveAWSConfidentialAMI(ctx, region)
	if err != nil {
		return nil, err
	}
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
	deps := awsDeps{
		provider:   a.provider,
		image:      ami,
		sshPubKey:  keyPath + ".pub",
		sshUser:    a.config.SSHUser,
		startAgent: awsStartAgent(a.agentBin, keyPath, a.config.SSHUser, egress, a.provider),
		waitReady:  waitForAgentEndpoint,
	}
	state, err := executeAWSConfidential(ctx, deps, p)
	if err != nil {
		return nil, err
	}
	return &adapter.RunHandle{ID: state.VMID, TargetID: a.targetID, State: state}, nil
}
