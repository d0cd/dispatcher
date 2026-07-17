package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	statedir "github.com/d0cd/dispatcher/internal/state"
)

// ProviderFirecracker identifies the local Firecracker microVM backend.
const ProviderFirecracker ProviderID = "firecracker"

// --- Firecracker machine config (config-file schema) -----------------------
//
// Firecracker is configured by a JSON document with kebab-case top-level keys
// and snake_case fields. See the Firecracker "Getting Started" config-file
// format. Only the fields dispatcher sets are modeled.

type fcBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type fcDrive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type fcMachineConfig struct {
	VCPUCount  int `json:"vcpu_count"`
	MemSizeMiB int `json:"mem_size_mib"`
}

type fcNetworkInterface struct {
	IfaceID     string `json:"iface_id"`
	GuestMAC    string `json:"guest_mac"`
	HostDevName string `json:"host_dev_name"`
}

// FirecrackerConfig is the JSON dispatcher writes for `firecracker --config-file`.
type FirecrackerConfig struct {
	BootSource        fcBootSource         `json:"boot-source"`
	Drives            []fcDrive            `json:"drives"`
	MachineConfig     fcMachineConfig      `json:"machine-config"`
	NetworkInterfaces []fcNetworkInterface `json:"network-interfaces,omitempty"`
}

// firecrackerVMSpec is the dispatcher-side input for a microVM.
type firecrackerVMSpec struct {
	KernelPath string
	RootfsPath string
	VCPUs      int
	MemMiB     int
	TapDevice  string // host tap interface; empty = no network interface
	GuestMAC   string
	BootArgs   string // empty = a sane serial-console default
}

// defaultFirecrackerBootArgs boots on the serial console (so we can capture boot
// logs), disables PCI, and panics/reboots fast on failure rather than hanging.
const defaultFirecrackerBootArgs = "console=ttyS0 reboot=k panic=1 pci=off"

// buildFirecrackerConfig turns a spec into the Firecracker config document,
// applying defaults (1 vCPU, 512 MiB, serial-console boot args). Pure.
func buildFirecrackerConfig(spec firecrackerVMSpec) FirecrackerConfig {
	vcpus := spec.VCPUs
	if vcpus <= 0 {
		vcpus = 1
	}
	mem := spec.MemMiB
	if mem <= 0 {
		mem = 512
	}
	bootArgs := spec.BootArgs
	if bootArgs == "" {
		bootArgs = defaultFirecrackerBootArgs
	}

	cfg := FirecrackerConfig{
		BootSource: fcBootSource{KernelImagePath: spec.KernelPath, BootArgs: bootArgs},
		Drives: []fcDrive{{
			DriveID:      "rootfs",
			PathOnHost:   spec.RootfsPath,
			IsRootDevice: true,
			IsReadOnly:   false,
		}},
		MachineConfig: fcMachineConfig{VCPUCount: vcpus, MemSizeMiB: mem},
	}
	if spec.TapDevice != "" {
		cfg.NetworkInterfaces = []fcNetworkInterface{{
			IfaceID:     "eth0",
			GuestMAC:    spec.GuestMAC,
			HostDevName: spec.TapDevice,
		}}
	}
	return cfg
}

// firecrackerLaunchArgs is the argv (after the binary) to boot a microVM from a
// config file, with the API socket kept for later control (shutdown). Pure.
func firecrackerLaunchArgs(apiSock, configPath string) []string {
	return []string{"--api-sock", apiSock, "--config-file", configPath}
}

// firecrackerKVMAvailable reports whether /dev/kvm is present as a char device.
// A seam so the preflight is testable off a KVM host.
var firecrackerKVMAvailable = func() bool {
	info, err := os.Stat("/dev/kvm")
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// fcRun runs a host command. A seam so orchestration is exercised with a stub in
// tests; on a KVM host it shells out for real.
var fcRun = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// fcSudo runs a privileged host command non-interactively (passwordless sudo is
// expected on a dedicated KVM host).
func fcSudo(ctx context.Context, name string, args ...string) ([]byte, error) {
	return fcRun(ctx, "sudo", append([]string{"-n", name}, args...)...)
}

// fcKernelPath/fcRootfsPath resolve the host-provided guest kernel and base
// rootfs from the environment. Required — CheckCLI fails closed if unset.
func fcKernelPath() string { return os.Getenv("DISPATCHER_FC_KERNEL") }
func fcRootfsPath() string { return os.Getenv("DISPATCHER_FC_ROOTFS") }

// fcRunDir is the per-run working directory (rootfs copy, config, socket, logs).
func fcRunDir(id string) (string, error) {
	return statedir.Subdir(filepath.Join("firecracker", id))
}

// fcAllocSubnetIndex picks a free /30 subnet index for a run and persists it in
// the run dir. It starts from the run's hash bucket and linear-probes so two
// concurrent runs whose ids collide mod 16384 don't land on the same host IP.
// GetVM/teardown read the persisted value via fcReadSubnetIndex.
func fcAllocSubnetIndex(id, dir string) (int, error) {
	used, err := fcUsedSubnetIndices(id)
	if err != nil {
		return 0, err
	}
	start := fcSubnetIndex(id)
	for i := 0; i < 16384; i++ {
		cand := (start + i) % 16384
		if used[cand] {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "subnet"), []byte(strconv.Itoa(cand)), 0o600); err != nil {
			return 0, err
		}
		return cand, nil
	}
	return 0, fmt.Errorf("no free firecracker /30 subnet (16384 in use)")
}

// fcUsedSubnetIndices returns the subnet indices in use by every run dir other
// than selfID, so allocation can avoid them.
func fcUsedSubnetIndices(selfID string) (map[int]bool, error) {
	used := map[int]bool{}
	base, err := statedir.Subdir("firecracker")
	if err != nil {
		return used, err
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return used, nil // no runs yet
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == selfID {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(base, e.Name(), "subnet")); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				used[n] = true
			}
		}
	}
	return used, nil
}

// fcReadSubnetIndex reads the persisted /30 index for a run, falling back to the
// hash bucket when no allocation was recorded (a partial/legacy run dir).
func fcReadSubnetIndex(id string) int {
	if dir, err := fcRunDir(id); err == nil {
		if b, err := os.ReadFile(filepath.Join(dir, "subnet")); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n >= 0 && n < 16384 {
				return n
			}
		}
	}
	return fcSubnetIndex(id)
}

// fcReadIface reads the host egress interface recorded at network setup, or ""
// when none was persisted.
func fcReadIface(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "iface"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// fcID derives a stable, charset-safe id used for the tap, MAC, and run dir. The
// per-run /30 subnet and the egress interface are allocated at create and
// persisted in the run dir (fcReadSubnetIndex/fcReadIface) so teardown removes
// exactly what create added even if the default route later changes.
func fcID(opts VMOptions) string {
	id := opts.Tags["dispatcher-run-id"]
	if id == "" {
		id = opts.Name
	}
	return adapter.SanitizeName(id)
}

// FirecrackerProvider runs workloads in local Firecracker microVMs. It is a
// local backend (like Lima): dispatcher runs on the KVM host and SSHes to the
// guest over a per-run tap. Privileged setup (tap, NAT, rootfs mount) goes
// through sudo.
type FirecrackerProvider struct{}

// NewFirecrackerProvider constructs the provider.
func NewFirecrackerProvider() *FirecrackerProvider {
	return &FirecrackerProvider{}
}

func (f *FirecrackerProvider) Name() ProviderID { return ProviderFirecracker }

// CheckCLI fails closed when the host can't run Firecracker — no binary, no
// /dev/kvm, or no configured kernel/rootfs — so `firecracker-vm` is cleanly
// infeasible rather than failing deep in provisioning.
func (f *FirecrackerProvider) CheckCLI(_ context.Context) error {
	if _, err := exec.LookPath("firecracker"); err != nil {
		return fmt.Errorf("firecracker binary not found in PATH: %w", err)
	}
	if !firecrackerKVMAvailable() {
		return fmt.Errorf("firecracker requires /dev/kvm (a Linux host with hardware virtualization)")
	}
	if fcKernelPath() == "" || fcRootfsPath() == "" {
		return fmt.Errorf("set DISPATCHER_FC_KERNEL and DISPATCHER_FC_ROOTFS to the guest kernel and base rootfs")
	}
	for _, p := range []string{fcKernelPath(), fcRootfsPath()} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("firecracker asset %q: %w", p, err)
		}
	}
	return nil
}

func (f *FirecrackerProvider) CreateVM(ctx context.Context, opts VMOptions) (retInfo *VMInfo, retErr error) {
	if err := f.CheckCLI(ctx); err != nil {
		return nil, err
	}
	id := fcID(opts)
	tap := fcTapName(id)
	mac := fcGuestMAC(id)

	// Clear any stale state from a prior run reusing this id.
	_ = f.teardown(ctx, id)

	dir, err := fcRunDir(id)
	if err != nil {
		return nil, err
	}

	// Allocate a free /30 (probing past hash collisions) and derive addresses.
	idx, err := fcAllocSubnetIndex(id, dir)
	if err != nil {
		return nil, err
	}
	hostIP, guestIP, mask := fcNetFromIndex(idx)
	cidr := fcCIDRFromIndex(idx)

	// Once host networking is up, any later failure must tear down the tap and
	// iptables rules — otherwise privileged host state leaks and needs manual
	// `ip link del` / `iptables -D`.
	netUp := false
	defer func() {
		if retErr != nil && netUp {
			_ = f.teardown(context.Background(), id)
		}
	}()

	// 1. Per-run rootfs copy so guest writes never touch the shared base.
	rootfs := filepath.Join(dir, "rootfs.ext4")
	if out, err := fcRun(ctx, "cp", "--reflink=auto", fcRootfsPath(), rootfs); err != nil {
		return nil, fmt.Errorf("copy rootfs: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// 2. Inject dispatcher's per-run public key into the rootfs copy.
	if opts.SSHKeyPath != "" {
		if err := fcInjectSSHKey(ctx, rootfs, opts.SSHKeyPath, dir); err != nil {
			return nil, err
		}
	}

	// 3. Host networking: tap on a per-run /30 + NAT for guest egress.
	if err := fcSetupNetwork(ctx, tap, hostIP, cidr, dir); err != nil {
		return nil, err
	}
	netUp = true

	// 4. Write the machine config (kernel ip= gives the guest its address).
	spec := firecrackerVMSpec{
		KernelPath: fcKernelPath(),
		RootfsPath: rootfs,
		VCPUs:      1,
		MemMiB:     512,
		TapDevice:  tap,
		GuestMAC:   mac,
		BootArgs:   fcBootArgsWithNet(defaultFirecrackerBootArgs, guestIP, hostIP, mask),
	}
	cfgPath := filepath.Join(dir, "config.json")
	data, err := json.MarshalIndent(buildFirecrackerConfig(spec), "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		return nil, err
	}

	// 5. Launch firecracker in the background (sudo: needs /dev/kvm + the tap).
	sock := filepath.Join(dir, "fc.sock")
	_, _ = fcSudo(ctx, "rm", "-f", sock)
	logf, err := os.Create(filepath.Join(dir, "console.log"))
	if err != nil {
		return nil, err
	}
	// Not CommandContext: the microVM must outlive this call; teardown stops it.
	launch := exec.Command("sudo", append([]string{"-n", "firecracker"},
		firecrackerLaunchArgs(sock, cfgPath)...)...)
	launch.Stdout = logf
	launch.Stderr = logf
	setProcessGroup(launch)
	if err := launch.Start(); err != nil {
		logf.Close()
		// The deferred cleanup tears down the tap/NAT on this error return.
		return nil, fmt.Errorf("launch firecracker: %w", err)
	}
	// Start has duplicated the fd into the child (its stdout/stderr); the parent's
	// copy is redundant now, so close it to avoid leaking one fd per microVM.
	logf.Close()

	return &VMInfo{
		ID:        id,
		IP:        guestIP,
		State:     VMStateRunning,
		CreatedAt: time.Now().UTC(),
		Tags:      opts.Tags,
	}, nil
}

func (f *FirecrackerProvider) WaitReady(ctx context.Context, _ string, ip string, _ string) error {
	return WaitForSSH(ctx, ip, 2*time.Minute)
}

func (f *FirecrackerProvider) GetVM(ctx context.Context, id string) (*VMInfo, error) {
	_, guestIP, _ := fcNetFromIndex(fcReadSubnetIndex(id))
	dir, err := fcRunDir(id)
	if err != nil {
		return &VMInfo{ID: id, IP: guestIP, State: VMStateTerminated}, nil
	}
	if _, err := fcRun(ctx, "pgrep", "-f", filepath.Join(dir, "config.json")); err != nil {
		return &VMInfo{ID: id, IP: guestIP, State: VMStateTerminated}, nil
	}
	return &VMInfo{ID: id, IP: guestIP, State: VMStateRunning}, nil
}

func (f *FirecrackerProvider) DestroyVM(ctx context.Context, id string) error {
	return f.teardown(ctx, id)
}

// teardown stops the microVM and removes its tap, NAT rules, and run dir. Every
// step is best-effort so a partial create still cleans up.
func (f *FirecrackerProvider) teardown(ctx context.Context, id string) error {
	dir, err := fcRunDir(id)
	if err != nil {
		return nil
	}
	_, _ = fcSudo(ctx, "pkill", "-f", filepath.Join(dir, "config.json"))
	tap := fcTapName(id)
	cidr := fcCIDRFromIndex(fcReadSubnetIndex(id))
	// Prefer the iface recorded at setup so the delete matches the insert even if
	// the default route changed; fall back to the current default route.
	iface := fcReadIface(dir)
	if iface == "" {
		iface, _ = fcDefaultIface(ctx)
	}
	if iface != "" {
		for _, c := range fcNATArgs(cidr, iface, tap, true) {
			_, _ = fcSudo(ctx, c[0], c[1:]...)
		}
	}
	for _, c := range fcTapDownArgs(tap) {
		_, _ = fcSudo(ctx, c[0], c[1:]...)
	}
	_, _ = fcSudo(ctx, "umount", filepath.Join(dir, "mnt"))
	_, _ = fcSudo(ctx, "rm", "-rf", dir)
	return nil
}

func (f *FirecrackerProvider) ListVMs(ctx context.Context, _ map[string]string) ([]VMInfo, error) {
	base, err := statedir.Subdir("firecracker")
	if err != nil {
		return nil, nil
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, nil
	}
	var out []VMInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if vm, err := f.GetVM(ctx, e.Name()); err == nil && vm.State == VMStateRunning {
			out = append(out, *vm)
		}
	}
	return out, nil
}

// fcInjectSSHKey mounts the rootfs copy and installs pubKey into root's
// authorized_keys so dispatcher can SSH into the guest.
func fcInjectSSHKey(ctx context.Context, rootfs, pubKeyPath, workDir string) error {
	pub, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}
	mnt := filepath.Join(workDir, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		return err
	}
	if out, err := fcSudo(ctx, "mount", "-o", "loop", rootfs, mnt); err != nil {
		return fmt.Errorf("mount rootfs: %s: %w", strings.TrimSpace(string(out)), err)
	}
	defer fcSudo(ctx, "umount", mnt)

	if out, err := fcSudo(ctx, "mkdir", "-p", filepath.Join(mnt, "root/.ssh")); err != nil {
		return fmt.Errorf("mkdir .ssh: %s: %w", strings.TrimSpace(string(out)), err)
	}
	akTmp := filepath.Join(workDir, "authorized_keys")
	if err := os.WriteFile(akTmp, pub, 0o600); err != nil {
		return err
	}
	ak := filepath.Join(mnt, "root/.ssh/authorized_keys")
	if out, err := fcSudo(ctx, "cp", akTmp, ak); err != nil {
		return fmt.Errorf("write authorized_keys: %s: %w", strings.TrimSpace(string(out)), err)
	}
	_, _ = fcSudo(ctx, "chmod", "700", filepath.Join(mnt, "root/.ssh"))
	_, _ = fcSudo(ctx, "chmod", "600", ak)
	return nil
}

// fcSetupNetwork brings up the per-run tap and NATs guest egress out the host's
// default interface. The chosen interface is persisted in dir so teardown can
// delete exactly the rules it added, even if the default route later changes.
func fcSetupNetwork(ctx context.Context, tap, hostIP, cidr, dir string) error {
	_, _ = fcSudo(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1")
	for _, c := range fcTapUpArgs(tap, hostIP) {
		if out, err := fcSudo(ctx, c[0], c[1:]...); err != nil {
			return fmt.Errorf("tap setup %v: %s: %w", c, strings.TrimSpace(string(out)), err)
		}
	}
	iface, err := fcDefaultIface(ctx)
	if err != nil {
		return err
	}
	// Record the egress iface before inserting the rules so teardown can remove
	// them by the exact spec even if the create later fails partway.
	_ = os.WriteFile(filepath.Join(dir, "iface"), []byte(iface), 0o600)
	for _, c := range fcNATArgs(cidr, iface, tap, false) {
		if out, err := fcSudo(ctx, c[0], c[1:]...); err != nil {
			return fmt.Errorf("nat setup %v: %s: %w", c, strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

// fcDefaultIface returns the host's default-route interface (for NAT).
func fcDefaultIface(ctx context.Context) (string, error) {
	out, err := fcRun(ctx, "sh", "-c", "ip route show default | awk '{print $5; exit}'")
	if err != nil {
		return "", err
	}
	iface := strings.TrimSpace(string(out))
	if iface == "" {
		return "", fmt.Errorf("could not determine default network interface")
	}
	return iface, nil
}
