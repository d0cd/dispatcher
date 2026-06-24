package cloudvm

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

type runCtxMarker struct{}

// On a provisioning failure the half-created VM must be destroyed, and the
// teardown must use a FRESH context — otherwise a cancelled run context (Ctrl-C
// during provisioning) would cancel the cleanup too and leak a billing VM.
func TestCloudVMExecute_DestroysVMWithFreshContextOnFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	mock := NewMockProvider(ProviderHetzner)
	mock.WaitErr = errors.New("ssh never came up")
	a := NewCloudVMAdapter(mock, Config{ProviderID: ProviderHetzner, Region: "fsn1"})

	runCtx := context.WithValue(context.Background(), runCtxMarker{}, "run")
	p := &types.Plan{
		Metadata: types.PlanMetadata{ID: "run_cleanup"},
		Workload: types.WorkloadSpec{Name: "job"},
	}

	_, err := a.Execute(runCtx, p)

	require.Error(t, err, "Execute must fail when the VM never becomes reachable")
	assert.Equal(t, 0, mock.VMCount(), "the half-created VM must be destroyed")
	require.NotNil(t, mock.DestroyCtx, "DestroyVM must have been called for cleanup")
	assert.Nil(t, mock.DestroyCtx.Value(runCtxMarker{}),
		"cleanup must use a fresh context, not the cancellable run context")
}
