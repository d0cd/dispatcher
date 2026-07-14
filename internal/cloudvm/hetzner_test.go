package cloudvm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DestroyVM must delete the per-run SSH key using the run id recovered BEFORE the
// server is deleted. Re-describing the already-deleted server (the old behavior)
// fails, so the key `dispatcher-<runID>` was never deleted and leaked on every run.
func TestHetznerDestroyVM_DeletesSSHKeyWithoutRedescribe(t *testing.T) {
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })

	var calls []string
	deleted := false
	runCLI = func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		calls = append(calls, cmd)
		switch {
		case strings.Contains(cmd, "server delete"):
			deleted = true
			return []byte("{}"), nil
		case strings.Contains(cmd, "server describe"):
			if deleted {
				return nil, errors.New("hcloud: server not found") // the real post-delete failure
			}
			return []byte(`{"labels":{"dispatcher-run-id":"run_abc"}}`), nil
		default:
			return []byte("{}"), nil
		}
	}

	h := NewHetznerProvider("hel1")
	require.NoError(t, h.DestroyVM(context.Background(), "srv-1"))

	joined := strings.Join(calls, " | ")
	assert.Contains(t, joined, "ssh-key delete dispatcher-run_abc", "per-run ssh key must be deleted via the pre-delete run id")
}

// Azure teardown must NOT delete the VM if it can't enumerate the VM's satellite
// resources — deleting it would orphan the untagged OS disk / public IP.
func TestAzureDestroyVM_AbortsWhenGatherFails(t *testing.T) {
	prevCLI := runCLI
	prevRetry := DefaultRetry
	t.Cleanup(func() { runCLI = prevCLI; DefaultRetry = prevRetry })
	DefaultRetry = RetryPolicy{MaxAttempts: 2, Initial: time.Millisecond, Max: time.Millisecond}

	deleteCalled := false
	runCLI = func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(cmd, "vm show"):
			return nil, errors.New("Retryable: service is temporarily unavailable, please retry")
		case strings.Contains(cmd, "vm delete"):
			deleteCalled = true
			return []byte("{}"), nil
		default:
			return []byte("{}"), nil
		}
	}
	p := NewAzureProvider("dispatcher-rg", "eastus")
	err := p.DestroyVM(context.Background(), "vm-1")
	require.Error(t, err, "teardown must abort when it can't enumerate satellites")
	assert.False(t, deleteCalled, "must not delete the VM (would orphan its untagged disk/IP)")
}
