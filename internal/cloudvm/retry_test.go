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

func TestRetry_SucceedsAfterTransientErrors(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), RetryPolicy{MaxAttempts: 4, Initial: time.Millisecond, Max: time.Millisecond}, IsTransient, func() error {
		calls++
		if calls < 3 {
			return errors.New("503 Service Unavailable")
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 3, calls)
}

func TestRetry_StopsOnNonTransient(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), RetryPolicy{MaxAttempts: 4, Initial: time.Millisecond}, IsTransient, func() error {
		calls++
		return errors.New("invalid credentials")
	})
	require.Error(t, err)
	assert.Equal(t, 1, calls, "non-transient error must not retry")
}

func TestRetry_ExhaustsAttempts(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), RetryPolicy{MaxAttempts: 3, Initial: time.Millisecond}, IsTransient, func() error {
		calls++
		return errors.New("throttled — rate limit exceeded")
	})
	require.Error(t, err)
	assert.Equal(t, 3, calls)
}

func TestRetry_CancelsOnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Retry(ctx, RetryPolicy{MaxAttempts: 5, Initial: time.Hour}, IsTransient, func() error {
		return errors.New("timeout")
	})
	assert.ErrorIs(t, err, context.Canceled)
}

func TestIsTransient_KnownMarkers(t *testing.T) {
	for _, msg := range []string{
		"503 Service Unavailable",
		"Too many requests",
		"connection reset by peer",
		"i/o timeout",
		"throttling",
		"rate limit exceeded",
	} {
		assert.True(t, IsTransient(errors.New(msg)), "expected transient: %q", msg)
	}
	for _, msg := range []string{
		"invalid credentials",
		"resource not found",
		"insufficient quota",
	} {
		assert.False(t, IsTransient(errors.New(msg)), "expected non-transient: %q", msg)
	}
}

// runCLI must surface the CLI's stderr, not just "exit status N", so operators
// can see why a teardown/list/get failed.
func TestRunCLI_SurfacesStderr(t *testing.T) {
	_, err := runCLI(context.Background(), "sh", "-c", "echo 'boom detail' >&2; exit 3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom detail")
}

// wrapExecError over an already-wrapped runCLI error must not repeat the stderr.
func TestWrapExecError_IdempotentOverRunCLI(t *testing.T) {
	_, err := runCLI(context.Background(), "sh", "-c", "echo 'boom detail' >&2; exit 3")
	require.Error(t, err)
	wrapped := wrapExecError("delete vm", err)
	assert.Contains(t, wrapped.Error(), "delete vm")
	assert.Equal(t, 1, strings.Count(wrapped.Error(), "boom detail"), "stderr must appear exactly once")
}

// adoptCreatedVM makes CreateVM idempotent: if a create CLI errored transiently
// after the instance was created, the run-tagged VM is adopted instead of leaked.
func TestAdoptCreatedVM(t *testing.T) {
	p := NewMockProvider(ProviderGCP)
	vm, err := p.CreateVM(context.Background(), VMOptions{
		Name: "x", Tags: map[string]string{"dispatcher-run-id": "run-1", "dispatcher": "true"},
	})
	require.NoError(t, err)

	adopted := adoptCreatedVM(context.Background(), p, "run-1")
	require.NotNil(t, adopted, "a run-tagged VM that exists must be adopted, not leaked")
	assert.Equal(t, vm.ID, adopted.ID)
	assert.NotEmpty(t, adopted.IP, "the adopted VM is hydrated via GetVM (has its IP)")

	assert.Nil(t, adoptCreatedVM(context.Background(), p, "run-none"), "a genuine create failure (no VM) surfaces the original error")
	assert.Nil(t, adoptCreatedVM(context.Background(), p, ""), "no run id to adopt by")
}
