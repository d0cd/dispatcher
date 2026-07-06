package cloudvm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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

// FirecrackerProvider runs workloads in local Firecracker microVMs. The offline
// core (config + argv + preflight) is built here; the live launch, tap
// networking, and rootfs/kernel provisioning land in a follow-up increment and
// require a Linux host with /dev/kvm.
type FirecrackerProvider struct{}

// NewFirecrackerProvider constructs the provider.
func NewFirecrackerProvider() *FirecrackerProvider {
	return &FirecrackerProvider{}
}

func (f *FirecrackerProvider) Name() ProviderID { return ProviderFirecracker }

// CheckCLI fails closed when the host can't run Firecracker — no binary or no
// /dev/kvm — so `firecracker-vm` is cleanly infeasible on a laptop rather than
// failing deep in provisioning.
func (f *FirecrackerProvider) CheckCLI(_ context.Context) error {
	if _, err := exec.LookPath("firecracker"); err != nil {
		return fmt.Errorf("firecracker binary not found in PATH: %w", err)
	}
	if !firecrackerKVMAvailable() {
		return fmt.Errorf("firecracker requires /dev/kvm (a Linux host with hardware virtualization)")
	}
	return nil
}

// errFirecrackerLive marks the lifecycle operations whose live implementation
// (microVM launch, tap networking, rootfs provisioning) requires a KVM host and
// lands in the next increment. The preflight above keeps these unreachable on
// unsupported hosts.
var errFirecrackerLive = fmt.Errorf("firecracker live provisioning requires a KVM host (not yet implemented)")

func (f *FirecrackerProvider) CreateVM(ctx context.Context, _ VMOptions) (*VMInfo, error) {
	if err := f.CheckCLI(ctx); err != nil {
		return nil, err
	}
	return nil, errFirecrackerLive
}

func (f *FirecrackerProvider) WaitReady(_ context.Context, _, _, _ string) error {
	return errFirecrackerLive
}

func (f *FirecrackerProvider) GetVM(_ context.Context, _ string) (*VMInfo, error) {
	return nil, errFirecrackerLive
}

func (f *FirecrackerProvider) DestroyVM(_ context.Context, _ string) error {
	return errFirecrackerLive
}

func (f *FirecrackerProvider) ListVMs(_ context.Context, _ map[string]string) ([]VMInfo, error) {
	return nil, errFirecrackerLive
}
