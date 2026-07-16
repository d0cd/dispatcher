package cloudvm

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOCIImageShapeHint(t *testing.T) {
	// OCI's raw arch-mismatch error is cryptic; the hint must name the required
	// architecture and the env var to fix so the operator can act.
	armErr := fmt.Errorf(`ServiceError: {"message": "Shape VM.Standard.A1.Flex is not valid for image ocid1.image.x86"}`)
	got := ociImageShapeHint("VM.Standard.A1.Flex", "ocid1.image.x86", armErr)
	assert.Contains(t, got.Error(), "aarch64")
	assert.Contains(t, got.Error(), "DISPATCHER_OCI_IMAGE_ID")

	// An x86 shape names x86_64.
	x86 := ociImageShapeHint("VM.Standard.E4.Flex", "img", fmt.Errorf("launch: not valid for image"))
	assert.Contains(t, x86.Error(), "x86_64")

	// Unrelated errors pass through untouched.
	other := fmt.Errorf("quota exceeded")
	assert.Equal(t, "quota exceeded", ociImageShapeHint("VM.Standard.A1.Flex", "img", other).Error())
}

func TestOCIShape(t *testing.T) {
	// Default general-purpose shape when the operator pins nothing.
	assert.Equal(t, "VM.Standard.E4.Flex", ociShape(VMOptions{}))
	// An explicit instance type wins.
	assert.Equal(t, "VM.Standard.E6.Flex", ociShape(VMOptions{InstanceType: "VM.Standard.E6.Flex"}))
}

func withOCIEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DISPATCHER_OCI_COMPARTMENT_ID", "ocid1.compartment.oc1..cccc")
	t.Setenv("DISPATCHER_OCI_AVAILABILITY_DOMAIN", "Uocm:PHX-AD-1")
	t.Setenv("DISPATCHER_OCI_SUBNET_ID", "ocid1.subnet.oc1..ssss")
	t.Setenv("DISPATCHER_OCI_IMAGE_ID", "ocid1.image.oc1..iiii")
}

func TestOCICreateVM_Argv(t *testing.T) {
	withOCIEnv(t)
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })

	var launchArgs []string
	runCLI = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "instance launch"):
			launchArgs = args
			return []byte(`{"data":{"id":"ocid1.instance.oc1..vvvv"}}`), nil
		case strings.Contains(joined, "list-vnics"):
			return []byte(`{"data":[{"public-ip":"203.0.113.7"}]}`), nil
		default:
			return []byte(`{"data":{}}`), nil
		}
	}

	o := NewOCIProvider("us-phoenix-1")
	vm, err := o.CreateVM(context.Background(), VMOptions{
		Name: "dispatcher-job",
		Tags: map[string]string{"dispatcher-run-id": "run_1", "dispatcher": "true"},
	})
	require.NoError(t, err)
	assert.Equal(t, "ocid1.instance.oc1..vvvv", vm.ID)
	assert.Equal(t, "203.0.113.7", vm.IP)

	a := strings.Join(launchArgs, " ")
	assert.Contains(t, a, "--compartment-id ocid1.compartment.oc1..cccc")
	assert.Contains(t, a, "--subnet-id ocid1.subnet.oc1..ssss")
	assert.Contains(t, a, "--image-id ocid1.image.oc1..iiii")
	assert.Contains(t, a, "--availability-domain Uocm:PHX-AD-1")
	assert.Contains(t, a, "--assign-public-ip true")
	assert.Contains(t, a, "--region us-phoenix-1")
	// OCI is a plain provisioning target: no confidential platform-config.
	assert.NotContains(t, a, "--platform-config")
}

func TestOCICreateVM_RequiresOCIDs(t *testing.T) {
	// No env set → the required OCIDs are missing → fail closed before any CLI call.
	o := NewOCIProvider("us-phoenix-1")
	_, err := o.CreateVM(context.Background(), VMOptions{Name: "x", Tags: map[string]string{"dispatcher-run-id": "r"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DISPATCHER_OCI_")
}

func TestOCICreateVM_PublicIPFailureUsesFreshCleanupContext(t *testing.T) {
	withOCIEnv(t)
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })

	cleanupCalled := false
	cleanupContextAlive := false
	runCLI = func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "instance launch"):
			return []byte(`{"data":{"id":"ocid1.instance.oc1..cleanup"}}`), nil
		case strings.Contains(joined, "list-vnics"):
			return nil, ctx.Err()
		case strings.Contains(joined, "instance terminate"):
			cleanupCalled = true
			cleanupContextAlive = ctx.Err() == nil
			return []byte(`{}`), nil
		default:
			return nil, fmt.Errorf("unexpected oci call: %s", joined)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewOCIProvider("us-phoenix-1").CreateVM(ctx, VMOptions{Name: "x"})
	require.Error(t, err)
	assert.True(t, cleanupCalled)
	assert.True(t, cleanupContextAlive, "cleanup must not reuse the canceled provisioning context")
}

func TestOCIGetVM_MapsLifecycleState(t *testing.T) {
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })
	runCLI = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "list-vnics") {
			return []byte(`{"data":[]}`), nil
		}
		return []byte(`{"data":{"id":"ocid1.instance.oc1..vvvv","lifecycle-state":"TERMINATED"}}`), nil
	}
	o := NewOCIProvider("us-phoenix-1")
	vm, err := o.GetVM(context.Background(), "ocid1.instance.oc1..vvvv")
	require.NoError(t, err)
	assert.Equal(t, VMStateTerminated, vm.State)
}

func TestOCIDestroyVM_TerminatesForce(t *testing.T) {
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })
	var got string
	runCLI = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		got = strings.Join(args, " ")
		return []byte("{}"), nil
	}
	o := NewOCIProvider("")
	require.NoError(t, o.DestroyVM(context.Background(), "ocid1.instance.oc1..vvvv"))
	assert.Contains(t, got, "instance terminate")
	assert.Contains(t, got, "--force")
}

func TestOCIListVMs_FiltersByFreeformTags(t *testing.T) {
	withOCIEnv(t)
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })
	runCLI = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(`{"data":[
			{"id":"a","lifecycle-state":"RUNNING","freeform-tags":{"dispatcher":"true","dispatcher-run-id":"run_1"}},
			{"id":"b","lifecycle-state":"RUNNING","freeform-tags":{"dispatcher":"true","dispatcher-run-id":"run_2"}},
			{"id":"c","lifecycle-state":"TERMINATED","freeform-tags":{"dispatcher":"true","dispatcher-run-id":"run_1"}}
		]}`), nil
	}
	o := NewOCIProvider("us-phoenix-1")
	vms, err := o.ListVMs(context.Background(), map[string]string{"dispatcher-run-id": "run_1"})
	require.NoError(t, err)
	require.Len(t, vms, 1, "only the running instance matching the run-id tag")
	assert.Equal(t, "a", vms[0].ID)
}

func TestOCIFlexSizing_FromCatalog(t *testing.T) {
	// A selected Flex SKU is sized from its catalog entry, not a fixed 2/16.
	o, m := ociFlexSizing("VM.Standard.E5.Flex")
	assert.Equal(t, 4, o)
	assert.Equal(t, 32.0, m)
	// An unknown shape falls back to the safe default.
	o2, m2 := ociFlexSizing("VM.Nonexistent.Flex")
	assert.Equal(t, 2, o2)
	assert.Equal(t, 16.0, m2)
}

// A launch whose --wait-for-state is cancelled after the instance was created
// must be reaped by its run tag, not leaked.
func TestOCICreateVM_ReapsLeakOnLaunchFailure(t *testing.T) {
	withOCIEnv(t)
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })
	terminated := ""
	runCLI = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "instance launch"):
			return nil, fmt.Errorf("context canceled during --wait-for-state")
		case strings.Contains(j, "instance list"):
			return []byte(`{"data":[{"id":"ocid1.instance.oc1..leaked","lifecycle-state":"RUNNING","freeform-tags":{"dispatcher-run-id":"run_leak"}}]}`), nil
		case strings.Contains(j, "instance terminate"):
			terminated = j
			return []byte("{}"), nil
		default:
			return []byte(`{"data":[]}`), nil
		}
	}
	o := NewOCIProvider("us-phoenix-1")
	_, err := o.CreateVM(context.Background(), VMOptions{Name: "x", Tags: map[string]string{"dispatcher-run-id": "run_leak", "dispatcher": "true"}})
	require.Error(t, err)
	assert.Contains(t, terminated, "instance terminate", "a leaked launch must be reaped by run tag")
	assert.Contains(t, terminated, "ocid1.instance.oc1..leaked")
}
