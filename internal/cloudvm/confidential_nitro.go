package cloudvm

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/attest/agent"
	statedir "github.com/d0cd/dispatcher/internal/state"
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
		opts := azureSSHOpts(keyPath) // same ssh/scp flags (accept-new TOFU)
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
	targetID     string
	provider     Provider
	eifPath      string // pre-built enclave image (deploy/nitro/build-eif.sh)
	proxyBin     string // cross-compiled dispatcher-nitro-proxy
	pcr0         string // pinned enclave-image measurement (from build-eif.sh)
	instanceType string
	config       Config
}

// NewAWSNitroConfidentialAdapter builds the adapter. eifPath is the pre-built,
// pinned EIF; proxyBin is the parent-side vsock proxy; pcr0 is that EIF's measured
// PCR0 (the attested identity).
func NewAWSNitroConfidentialAdapter(provider Provider, eifPath, proxyBin, pcr0, instanceType string, cfg Config) *AWSNitroConfidentialAdapter {
	if instanceType == "" {
		instanceType = defaultNitroInstanceType
	}
	return &AWSNitroConfidentialAdapter{
		targetID: string(cfg.ProviderID) + "-nitro",
		provider: provider, eifPath: eifPath, proxyBin: proxyBin, pcr0: pcr0,
		instanceType: instanceType, config: cfg,
	}
}

func (a *AWSNitroConfidentialAdapter) ID() string { return a.targetID }

func (a *AWSNitroConfidentialAdapter) Execute(ctx context.Context, p *types.Plan) (*adapter.RunHandle, error) {
	if a.eifPath == "" || a.proxyBin == "" || a.pcr0 == "" {
		return nil, fmt.Errorf("nitro adapter needs a pinned EIF, proxy binary, and PCR0 (build with deploy/nitro/build-eif.sh)")
	}
	region := p.Constraints.Region
	if region == "" {
		region = a.config.Region
	}
	if rp, ok := a.provider.(regionalProvider); ok && region != "" {
		rp.SetRegion(region)
	}
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

	deps := nitroDeps{
		provider:     a.provider,
		image:        ami,
		instanceType: a.instanceType,
		pcr0:         a.pcr0,
		sshPubKey:    keyPath + ".pub",
		sshUser:      a.config.SSHUser,
		startAgent:   nitroStartAgent(a.eifPath, a.proxyBin, keyPath, a.config.SSHUser, detectEgressCIDR(ctx), a.provider),
		waitReady:    waitForAgentEndpoint,
	}
	state, err := executeNitroConfidential(ctx, deps, p)
	if err != nil {
		return nil, err
	}
	return &adapter.RunHandle{ID: state.VMID, TargetID: a.targetID, State: state}, nil
}

func (a *AWSNitroConfidentialAdapter) Validate(ctx context.Context, _ types.WorkloadSpec) (types.ValidationResult, error) {
	v := types.ValidationResult{
		Schema: types.ValidationPass, PackageBuild: types.ValidationPass,
		TargetCapabilities: types.ValidationPass, Credentials: types.ValidationPass,
		Quota: types.ValidationSkipped, Network: types.ValidationPass,
		Policy: types.ValidationPass, CostEstimate: types.ValidationPass, CleanupPlan: types.ValidationPass,
	}
	if err := a.provider.CheckCLI(ctx); err != nil {
		v.Credentials = types.ValidationFail
		return v, fmt.Errorf("provider CLI check failed: %w", err)
	}
	return v, nil
}

func (a *AWSNitroConfidentialAdapter) EstimateCost(_ context.Context, w types.WorkloadSpec) (types.CostEstimate, error) {
	hours := 1.0
	if w.DetectedKind == types.WorkloadKindService {
		hours = 24.0
	}
	total := providerBaseRate(a.config.ProviderID) * hours
	return types.CostEstimate{
		Value: float64(int(total*1000)) / 1000, Currency: "USD", Confidence: types.ConfidenceMedium,
		Assumptions: []string{fmt.Sprintf("assumes %.0fh runtime", hours), "Nitro Enclaves parent instance (measured enclave)"},
		Exclusions:  []string{"excludes network egress", "excludes storage"},
	}, nil
}

func (a *AWSNitroConfidentialAdapter) Prepare(context.Context, *types.Plan) error { return nil }

func (a *AWSNitroConfidentialAdapter) Status(_ context.Context, h *adapter.RunHandle) (types.RunState, error) {
	if h.State.(*confidentialRunState).Result.ExitCode != 0 {
		return types.RunStateExecutionFailed, nil
	}
	return types.RunStateCompleted, nil
}

func (a *AWSNitroConfidentialAdapter) FailureDetails(h *adapter.RunHandle) adapter.FailureDetails {
	state, ok := h.State.(*confidentialRunState)
	if !ok {
		return adapter.FailureDetails{Message: "no confidential run state"}
	}
	fd := adapter.FailureDetails{ExitCode: state.Result.ExitCode}
	if state.Result.ExitCode != 0 {
		fd.Message = fmt.Sprintf("confidential workload exited with code %d", state.Result.ExitCode)
	}
	return fd
}

func (a *AWSNitroConfidentialAdapter) Logs(_ context.Context, h *adapter.RunHandle, w io.Writer) error {
	state := h.State.(*confidentialRunState)
	if len(state.Result.Stdout) > 0 {
		_, _ = w.Write(state.Result.Stdout)
	}
	if len(state.Result.Stderr) > 0 {
		_, _ = w.Write(state.Result.Stderr)
	}
	return nil
}

func (a *AWSNitroConfidentialAdapter) Artifacts(_ context.Context, h *adapter.RunHandle) ([]adapter.ArtifactRef, error) {
	state := h.State.(*confidentialRunState)
	if len(state.Result.OutputsTarGz) == 0 {
		return nil, nil
	}
	indexKey := h.RunID
	if indexKey == "" {
		indexKey = h.ID
	}
	dest, err := statedir.Subdir(filepath.Join("runs", indexKey, "artifacts"))
	if err != nil {
		return nil, fmt.Errorf("create artifacts dir: %w", err)
	}
	if err := agent.UnTarGz(state.Result.OutputsTarGz, dest); err != nil {
		return nil, fmt.Errorf("extract outputs: %w", err)
	}
	var refs []adapter.ArtifactRef
	_ = filepath.Walk(dest, func(pth string, info os.FileInfo, _ error) error {
		if info == nil || info.IsDir() {
			return nil
		}
		refs = append(refs, adapter.ArtifactRef{Name: filepath.Base(pth), Path: pth, Size: info.Size()})
		return nil
	})
	return refs, nil
}

func (a *AWSNitroConfidentialAdapter) Terminate(context.Context, *adapter.RunHandle) error {
	return nil
}

func (a *AWSNitroConfidentialAdapter) Cleanup(ctx context.Context, h *adapter.RunHandle) (*adapter.CleanupResult, error) {
	state := h.State.(*confidentialRunState)
	// Terminating the parent instance tears down the enclave with it.
	if err := a.provider.DestroyVM(ctx, state.VMID); err != nil {
		return &adapter.CleanupResult{Success: false, Errors: []string{err.Error()}}, nil
	}
	return &adapter.CleanupResult{Success: true, ResourcesCleaned: []string{state.VMID}}, nil
}
