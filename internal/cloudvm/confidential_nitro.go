package cloudvm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/types"
)

// The Nitro enclave parameters. The parent is a plain enclave-enabled instance;
// the enclave it launches is the measured TEE. CID/port are fixed per run (one
// enclave per parent); memory is the enclave's fixed RAM — raise it for heavier
// workloads (the enclave has no swap and no disk).
const (
	defaultNitroInstanceType = "c6a.xlarge"
	nitroEnclaveCID          = 16
	nitroEnclaveCPUs         = 2
	nitroEnclaveMemoryMiB    = 768
)

// nitroDeps are the AWS Nitro confidential run's collaborators (see
// sshConfidentialDeps). pcr0 is the pinned enclave-image measurement.
type nitroDeps struct {
	provider     Provider
	image        string
	instanceType string
	pcr0         string
	sshPubKey    string
	sshUser      string
	startAgent   func(ctx context.Context, vm *VMInfo) (string, error)
	waitReady    func(ctx context.Context, baseURL string) error
}

// executeNitroConfidential is the AWS Nitro orchestration: the shared SSH-VM flow,
// but the parent is a plain enclave-enabled instance (no memory encryption) and
// verification is the Nitro attestation document (COSE → pinned Root-G1 + PCR0)
// over the parent's vsock proxy.
func executeNitroConfidential(ctx context.Context, d nitroDeps, p *types.Plan) (*confidentialRunState, error) {
	deps := sshConfidentialDeps{
		provider: d.provider, image: d.image, enclave: true, instanceType: d.instanceType,
		sshPubKey: d.sshPubKey, sshUser: d.sshUser,
		startAgent: d.startAgent, waitReady: d.waitReady,
		verify: func(ctx context.Context, _ *VMInfo, baseURL string, req types.ConfidentialRequirement) (attest.AttestationResult, error) {
			return attest.NewAWSNitroAttester(map[int]string{0: d.pcr0}, baseURL).Verify(ctx, req)
		},
	}
	return executeSSHConfidential(ctx, deps, p, fmt.Sprintf("dispatcher-nitro-%s", adapter.SanitizeName(p.Workload.Name)))
}

// nitroStartAgent returns a startAgent that, on a booted enclave-enabled parent:
// installs nitro-cli + the allocator, ships the pinned EIF and the vsock proxy,
// runs the enclave, and starts the proxy bridging the parent's TCP :8443 to the
// enclave's vsock. Unlike the SEV-SNP path the agent here IS measured — the
// enclave image's PCR0 is the attested identity — so a swapped EIF fails PCR0.
func nitroStartAgent(eifPath, proxyBin, keyPath, sshUser, egressCIDR string, provider Provider) func(context.Context, *VMInfo) (string, error) {
	return func(ctx context.Context, vm *VMInfo) (string, error) {
		if err := provider.WaitReady(ctx, vm.ID, vm.IP, keyPath); err != nil {
			return "", fmt.Errorf("wait for ssh: %w", err)
		}
		opts := confidentialAgentSSHOpts(keyPath)
		target := sshUser + "@" + vm.IP

		// Install + configure the Nitro allocator (the EIF is pre-built and pinned,
		// so no docker/build is needed on the parent).
		setup := "sudo dnf install -y -q aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel && " +
			"printf -- '---\\nmemory_mib: 1024\\ncpu_count: 2\\n' | sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null && " +
			"sudo systemctl enable --now nitro-enclaves-allocator.service"
		if out, err := exec.CommandContext(ctx, "ssh", append(append([]string{}, opts...), target, setup)...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("install nitro-cli: %s: %w", strings.TrimSpace(string(out)), err)
		}

		for _, f := range [][2]string{{eifPath, "/tmp/agent.eif"}, {proxyBin, "/tmp/nitro-proxy"}} {
			scpArgs := append(append([]string{}, opts...), f[0], target+":"+f[1])
			if out, err := exec.CommandContext(ctx, "scp", scpArgs...).CombinedOutput(); err != nil {
				return "", fmt.Errorf("scp %s: %s: %w", filepath.Base(f[0]), strings.TrimSpace(string(out)), err)
			}
		}

		run := fmt.Sprintf("sudo nitro-cli terminate-enclave --all >/dev/null 2>&1 || true; "+
			"sudo nitro-cli run-enclave --eif-path /tmp/agent.eif --cpu-count %d --memory %d --enclave-cid %d && "+
			"chmod +x /tmp/nitro-proxy && sudo bash -c 'nohup /tmp/nitro-proxy --tcp :%d --cid %d --vsock-port %d >/tmp/nitro-proxy.log 2>&1 &' && sleep 2",
			nitroEnclaveCPUs, nitroEnclaveMemoryMiB, nitroEnclaveCID, csAgentPort, nitroEnclaveCID, csAgentPort)
		if out, err := exec.CommandContext(ctx, "ssh", append(append([]string{}, opts...), target, run)...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("run enclave: %s: %w", strings.TrimSpace(string(out)), err)
		}

		if op, ok := provider.(awsPortOpener); ok && egressCIDR != "" {
			if err := op.OpenAgentPort(ctx, vm.ID, csAgentPort, egressCIDR); err != nil {
				return "", fmt.Errorf("open agent port: %w", err)
			}
		}
		return fmt.Sprintf("http://%s:%d", vm.IP, csAgentPort), nil
	}
}

// resolveAWSNitroAMI returns the Amazon Linux 2023 AMI (which packages
// aws-nitro-enclaves-cli via dnf) for the region — the operator override or SSM.
func resolveAWSNitroAMI(ctx context.Context, region string) (string, error) {
	if a := os.Getenv("DISPATCHER_AWS_NITRO_AMI"); a != "" {
		return a, nil
	}
	out, err := runCLI(ctx, "aws", "ssm", "get-parameters", "--region", region,
		"--names", "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
		"--query", "Parameters[0].Value", "--output", "text")
	if err != nil {
		return "", fmt.Errorf("resolve AL2023 AMI: %w", err)
	}
	ami := strings.TrimSpace(string(out))
	if !strings.HasPrefix(ami, "ami-") {
		return "", fmt.Errorf("unexpected AMI %q", ami)
	}
	return ami, nil
}

// AWSNitroConfidentialAdapter runs a workload inside an AWS Nitro Enclave, attested
// by the enclave image's measurement (PCR0, chained to the pinned AWS Nitro root)
// and sealed (R9). Unlike the SEV-SNP path the agent is measured, so this closes
// the agent-not-measured caveat — at the cost of the enclave execution model (no
// network/disk; self-contained workloads only). See docs/confidential-nitro.md.
type AWSNitroConfidentialAdapter struct {
	confidentialVMAdapter
	eifPath      string // pre-built enclave image (deploy/nitro/build-eif.sh)
	proxyBin     string // cross-compiled dispatcher-nitro-proxy
	pcr0         string // pinned enclave-image measurement (from build-eif.sh)
	instanceType string
}

// NewAWSNitroConfidentialAdapter builds the adapter. eifPath is the pre-built,
// pinned EIF; proxyBin is the parent-side vsock proxy; pcr0 is that EIF's measured
// PCR0 (the attested identity).
func NewAWSNitroConfidentialAdapter(provider Provider, eifPath, proxyBin, pcr0, instanceType string, cfg Config) *AWSNitroConfidentialAdapter {
	if instanceType == "" {
		instanceType = defaultNitroInstanceType
	}
	return &AWSNitroConfidentialAdapter{
		confidentialVMAdapter: confidentialVMAdapter{
			targetID: string(cfg.ProviderID) + "-nitro",
			provider: provider, config: cfg,
			costAssumption: "Nitro Enclaves parent instance (measured enclave)",
		},
		eifPath: eifPath, proxyBin: proxyBin, pcr0: pcr0, instanceType: instanceType,
	}
}

func (a *AWSNitroConfidentialAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	if a.eifPath == "" || a.proxyBin == "" || a.pcr0 == "" {
		return nil, fmt.Errorf("nitro adapter needs a pinned EIF, proxy binary, and PCR0 (build with deploy/nitro/build-eif.sh)")
	}
	region := a.resolveRegion(p)
	ami, err := resolveAWSNitroAMI(ctx, region)
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
	deps := nitroDeps{
		provider:     a.provider,
		image:        ami,
		instanceType: a.instanceType,
		pcr0:         a.pcr0,
		sshPubKey:    keyPath + ".pub",
		sshUser:      a.config.SSHUser,
		startAgent:   nitroStartAgent(a.eifPath, a.proxyBin, keyPath, a.config.SSHUser, egress, a.provider),
		waitReady:    waitForAgentEndpoint,
	}
	state, err := executeNitroConfidential(ctx, deps, p)
	if err != nil {
		return nil, err
	}
	return &adapter.RunHandle{ID: state.VMID, TargetID: a.targetID, State: state}, nil
}
