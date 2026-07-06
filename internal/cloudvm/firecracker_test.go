package cloudvm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withKVMAvailable overrides the /dev/kvm probe for the test's duration.
func withKVMAvailable(t *testing.T, available bool) {
	t.Helper()
	prev := firecrackerKVMAvailable
	firecrackerKVMAvailable = func() bool { return available }
	t.Cleanup(func() { firecrackerKVMAvailable = prev })
}

// withFakeBinaryInPath puts an executable of the given name on a fresh PATH so
// exec.LookPath finds it without invoking a real binary.
func withFakeBinaryInPath(t *testing.T, name string) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755))
	t.Setenv("PATH", dir)
}

func TestBuildFirecrackerConfig(t *testing.T) {
	cfg := buildFirecrackerConfig(firecrackerVMSpec{
		KernelPath: "/img/vmlinux",
		RootfsPath: "/img/rootfs.ext4",
		VCPUs:      2,
		MemMiB:     1024,
		TapDevice:  "fc-tap0",
		GuestMAC:   "AA:FC:00:00:00:01",
	})

	assert.Equal(t, "/img/vmlinux", cfg.BootSource.KernelImagePath)
	assert.Contains(t, cfg.BootSource.BootArgs, "console=ttyS0", "serial console for boot logs")
	require.Len(t, cfg.Drives, 1)
	assert.Equal(t, "/img/rootfs.ext4", cfg.Drives[0].PathOnHost)
	assert.True(t, cfg.Drives[0].IsRootDevice)
	assert.False(t, cfg.Drives[0].IsReadOnly, "rootfs is writable so the workload can run")
	assert.Equal(t, 2, cfg.MachineConfig.VCPUCount)
	assert.Equal(t, 1024, cfg.MachineConfig.MemSizeMiB)
	require.Len(t, cfg.NetworkInterfaces, 1)
	assert.Equal(t, "fc-tap0", cfg.NetworkInterfaces[0].HostDevName)
	assert.Equal(t, "AA:FC:00:00:00:01", cfg.NetworkInterfaces[0].GuestMAC)

	// It serializes with Firecracker's kebab-case top-level keys.
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	for _, key := range []string{"boot-source", "machine-config", "network-interfaces", "kernel_image_path", "mem_size_mib"} {
		assert.Contains(t, string(raw), key, "config JSON must use Firecracker's schema key %q", key)
	}
}

func TestBuildFirecrackerConfig_Defaults(t *testing.T) {
	cfg := buildFirecrackerConfig(firecrackerVMSpec{KernelPath: "/k", RootfsPath: "/r"})
	assert.Equal(t, 1, cfg.MachineConfig.VCPUCount, "defaults to 1 vCPU")
	assert.Equal(t, 512, cfg.MachineConfig.MemSizeMiB, "defaults to 512 MiB")
	assert.NotEmpty(t, cfg.BootSource.BootArgs)
	// No network interface when no tap device is given.
	assert.Empty(t, cfg.NetworkInterfaces)
}

func TestFirecrackerLaunchArgs(t *testing.T) {
	assert.Equal(t,
		[]string{"--api-sock", "/run/fc.sock", "--config-file", "/run/config.json"},
		firecrackerLaunchArgs("/run/fc.sock", "/run/config.json"))
}

func TestFirecrackerProvider_CheckCLI_FailsClosedOffKVM(t *testing.T) {
	// No /dev/kvm → infeasible with a clear reason, never a mysterious deep fault.
	// (Binary present so we isolate the KVM check, which is probed second.)
	withFakeBinaryInPath(t, "firecracker")
	withKVMAvailable(t, false)
	err := NewFirecrackerProvider().CheckCLI(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kvm")
}

func TestFirecrackerProvider_CheckCLI_OKWhenKVMAndBinaryPresent(t *testing.T) {
	withKVMAvailable(t, true)
	withFakeBinaryInPath(t, "firecracker")
	assert.NoError(t, NewFirecrackerProvider().CheckCLI(context.Background()))
}

func TestFirecrackerProvider_CheckCLI_FailsWithoutBinary(t *testing.T) {
	withKVMAvailable(t, true)
	// Empty PATH → firecracker binary not found.
	t.Setenv("PATH", t.TempDir())
	err := NewFirecrackerProvider().CheckCLI(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "firecracker")
}

func TestFirecrackerProvider_CreateVM_FailsClosedOffKVM(t *testing.T) {
	// CreateVM gates on CheckCLI, so provisioning never starts off a KVM host.
	withFakeBinaryInPath(t, "firecracker")
	withKVMAvailable(t, false)
	_, err := NewFirecrackerProvider().CreateVM(context.Background(), VMOptions{Name: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kvm")
}

func TestFirecrackerProvider_Name(t *testing.T) {
	assert.Equal(t, ProviderFirecracker, NewFirecrackerProvider().Name())
}
