package cloudvm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/types"
)

// sshConfidentialDeps are the collaborators for an SSH-VM confidential run
// (azure-snp, AWS Nitro). The provider-specific verification is a closure so the
// same orchestration serves both; the live ops (provision, start-agent, endpoint
// reachability) are seams so the verify-before-deliver ordering is unit-testable.
type sshConfidentialDeps struct {
	provider Provider
	image    string // optional VM image override (AWS pins a SEV-SNP 24.04 AMI)
	// confidential is VMOptions.ConfidentialType: "sev-snp" for a memory-encrypted
	// CVM (azure-snp), or "" for a Nitro Enclaves parent (the parent is a plain
	// instance — the measured enclave it launches is the TEE).
	confidential  string
	enclave       bool   // request Nitro Enclaves support on the parent
	secureBootOff bool   // Secure Boot off (the Azure direct-SNP unsigned UKI image)
	instanceType  string // optional; a Nitro parent pins an enclave-capable type
	sshPubKey     string
	// sshKeyPath is the private key for renewing the self-destruct watchdog over
	// SSH during the synchronous run. Set only for backends whose VM exposes SSH
	// (the Nitro parent); empty for the measured CVM path, which ships no login.
	sshKeyPath string
	sshUser    string
	startAgent func(ctx context.Context, vm *VMInfo) (baseURL string, err error)
	waitReady  func(ctx context.Context, baseURL string) error
	// validator builds the provider's aTLS attestation validator (azure-snp SNP+
	// vTPM, Nitro doc) for a run; it records the verified verdict as it validates
	// the evidence delivered over the attested TLS session.
	validator func(req types.ConfidentialRequirement) *attest.AttestValidator
}

// extendWatchdog is the watchdog-renewal seam (stubbed in tests).
var extendWatchdog = ExtendWatchdogViaSSH

// renewWatchdogUntil pushes out the VM's self-destruct deadline every ttl/3 until
// stop is closed or ctx is cancelled. A failed renewal is logged, not fatal — the
// VM's own boot-relative deadline is the backstop.
func renewWatchdogUntil(ctx context.Context, st *CloudVMState, ttl time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(ttl / 3)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			if _, err := extendWatchdog(rctx, st, ttl); err != nil {
				dlog.L().Warn("sshconf.watchdog.renew.failed", "vm_id", st.VMID, "err", err.Error())
			}
			cancel()
		}
	}
}

// executeSSHConfidential is the shared SSH-VM confidential orchestration:
// provision the VM, start the in-TEE agent, then attest and deliver source/.env +
// run the workload over one attested TLS session. Any failure before a verified
// verdict tears the VM down and never ships a secret.
func executeSSHConfidential(ctx context.Context, d sshConfidentialDeps, p *types.Plan, vmName string) (*confidentialRunState, error) {
	w := p.Workload

	// Fail closed on GPU, exactly as the plain adapter does (validateGPUInstance):
	// this path forces a CPU-only CVM SKU and has no confidential GPU inventory, so
	// a GPU workload that reaches here (e.g. a hand-forced target bypassing
	// feasibility) must be refused rather than silently run CPU-only on a costly VM.
	if err := validateGPUInstance(w, d.instanceType); err != nil {
		return nil, err
	}

	payload, err := buildConfidentialPayload(w)
	if err != nil {
		return nil, fmt.Errorf("build workload payload: %w", err)
	}

	region := p.Constraints.Region
	// Install the self-destruct watchdog, exactly as the regular cloud path does:
	// if the dispatcher CLI is killed mid-run (SIGKILL/OOM/power loss) this is the
	// only thing that stops an expensive confidential (possibly GPU) VM from
	// billing indefinitely. Launch measurement covers firmware/image, not
	// post-boot user-data, so this does not affect attestation.
	ttl := DefaultWatchdogTTL
	if p.Constraints.WatchdogTTL > 0 {
		ttl = p.Constraints.WatchdogTTL
	}
	opts := VMOptions{
		Name:               vmName,
		Region:             region,
		Image:              d.image,
		InstanceType:       d.instanceType,
		ConfidentialType:   d.confidential,
		EnclaveEnabled:     d.enclave,
		SecureBootDisabled: d.secureBootOff,
		SSHKeyPath:         d.sshPubKey,
		SSHUser:            d.sshUser,
		UserData:           WatchdogCloudInit(ttl, d.sshUser, DefaultWatchdogSelfDestruct),
		Tags: map[string]string{
			"dispatcher-run-id": p.Metadata.ID,
			"dispatcher":        "true",
		},
	}

	dlog.L().Info("sshconf.create.start", "run", p.Metadata.ID, "provider", string(d.provider.Name()))
	vm, err := d.provider.CreateVM(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("provision confidential VM: %w", err)
	}
	destroyOnErr := true
	defer func() {
		if !destroyOnErr {
			return
		}
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = d.provider.DestroyVM(cctx, vm.ID)
	}()

	// The run below is synchronous, so the executor's watchdog renewal (which only
	// runs for durable adapters, after Execute returns) never fires here. Renew the
	// boot-relative deadline ourselves for the duration of the run, so a long-but-
	// live confidential job isn't hard-killed by the default TTL. Renewal stops when
	// this returns (or ctx is cancelled), so a dead CLI still lets the VM
	// self-destruct at the last deadline. Only backends that expose SSH (the Nitro
	// parent) can renew; the measured CVM ships no login and relies on gc.
	if d.sshKeyPath != "" {
		st := &CloudVMState{VMID: vm.ID, IP: vm.IP, SSHKeyPath: d.sshKeyPath, SSHUser: d.sshUser}
		// Pin the parent's host key so renewal SSH uses StrictHostKeyChecking=yes
		// against it rather than the permissive /dev/null fallback (which would let
		// a MITM intercept the deadline-extension). Best-effort: a keyscan failure
		// leaves renewal running, backstopped by the VM's own boot-relative deadline.
		if err := PinHostKey(ctx, st, p.Metadata.ID); err != nil {
			dlog.L().Warn("sshconf.watchdog.pin_host_key.failed", "run", p.Metadata.ID, "err", err.Error())
		}
		stopRenew := make(chan struct{})
		defer close(stopRenew)
		go renewWatchdogUntil(ctx, st, ttl, stopRenew)
	}

	baseURL, err := d.startAgent(ctx, vm)
	if err != nil {
		return nil, fmt.Errorf("start in-TEE agent: %w", err)
	}
	if err := d.waitReady(ctx, baseURL); err != nil {
		return nil, fmt.Errorf("confidential agent endpoint not reachable: %w", err)
	}

	// Attest AND deliver over one attested TLS session: verification, workload
	// delivery, and the result all ride the aTLS session bound to the agent's key.
	// Nothing is shipped before verification (runOverATLS aborts on a bad peer).
	v := d.validator(w.Requirements.Confidential)
	runRes, err := runOverATLS(ctx, strings.TrimPrefix(baseURL, "http://"), v, payload)
	if err != nil {
		return nil, fmt.Errorf("attested aTLS run: %w", err)
	}
	result := v.Result
	dlog.L().Info("sshconf.attested", "run", p.Metadata.ID, "vm_id", vm.ID, "measurement", result.Measurement)

	destroyOnErr = false
	return &confidentialRunState{
		Provider:    d.provider.Name(),
		VMID:        vm.ID,
		Region:      region,
		Outputs:     w.Outputs,
		Result:      runRes,
		Attestation: result,
		CreatedAt:   time.Now().UTC(),
	}, nil
}
