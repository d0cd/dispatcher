package cloudvm

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allProviders() []Provider {
	return []Provider{
		NewGCPProvider("proj", "zone"),
		NewAzureProvider("rg", "loc"),
		NewAWSProvider("us-east-1"),
		NewHetznerProvider("hel1"),
	}
}

// GetVM's contract: a "not found" describe result means the VM is gone, so every
// provider must report State=Terminated with no error.
func TestGetVM_NotFoundIsTerminated(t *testing.T) {
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })
	runCLI = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("instance 'vm-1' was not found")
	}
	for _, p := range allProviders() {
		vm, err := p.GetVM(context.Background(), "vm-1")
		require.NoError(t, err, "%T must map not-found to Terminated", p)
		require.NotNil(t, vm)
		assert.Equal(t, VMStateTerminated, vm.State, "%T", p)
	}
}

// isVMNotFound must key off the VM id, so a not-found for something else — a
// missing CLI binary or a wrong resource group — is NOT misread as the VM being
// gone (which would stop teardown and leak a live, billing VM).
func TestIsVMNotFound_RequiresTheVMID(t *testing.T) {
	// Real VM not-found (names the VM) → true.
	assert.True(t, isVMNotFound(errors.New("The Resource 'vm-1' was not found"), "vm-1"))
	assert.True(t, isVMNotFound(errors.New(`jobs.batch "vm-1" not found`), "vm-1"))
	// Wrong resource group (names the RG, not the VM) → false.
	assert.False(t, isVMNotFound(errors.New("Resource group 'other-rg' could not be found."), "vm-1"))
	// Missing CLI binary → false (does not name the VM).
	assert.False(t, isVMNotFound(errors.New(`exec: "az": executable file not found in $PATH`), "vm-1"))
	// A different VM's not-found → false.
	assert.False(t, isVMNotFound(errors.New("instance 'vm-2' not found"), "vm-1"))
	// A transient error → false.
	assert.False(t, isVMNotFound(errors.New("ServiceUnavailable: rate limited"), "vm-1"))
}

// A transient/auth error is NOT proof the VM is gone; every provider must
// propagate it rather than silently reporting Terminated.
func TestGetVM_TransientErrorPropagates(t *testing.T) {
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })
	runCLI = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("ServiceUnavailable: rate limited, please retry")
	}
	for _, p := range allProviders() {
		_, err := p.GetVM(context.Background(), "vm-1")
		assert.Error(t, err, "%T must propagate a transient error, not report Terminated", p)
	}
}
