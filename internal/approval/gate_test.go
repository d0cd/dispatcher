package approval

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestState(t *testing.T) {
	t.Helper()
	t.Setenv("DISPATCHER_HOME", t.TempDir())
}

func TestGate_InProcessApproval(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_inproc", []types.PolicyRequirement{{Name: "gpu", Reason: "h100"}})
	require.NoError(t, err)
	defer g.Close()

	approver := func(reqs []types.PolicyRequirement) (string, error) {
		assert.Len(t, reqs, 1)
		return "alice", nil
	}

	rec, err := g.Wait(context.Background(), approver)
	require.NoError(t, err)
	assert.Equal(t, DecisionApproved, rec.Decision)
	assert.Equal(t, "alice", rec.Decider)
	assert.Equal(t, "run_inproc", rec.RunID)
	assert.False(t, rec.DecidedAt.IsZero())
}

func TestGate_InProcessDenial(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_deny", nil)
	require.NoError(t, err)
	defer g.Close()

	approver := func(_ []types.PolicyRequirement) (string, error) {
		return "bob", ErrDenied
	}

	rec, err := g.Wait(context.Background(), approver)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDenied))
	assert.Equal(t, DecisionDenied, rec.Decision)
	assert.Equal(t, "bob", rec.Decider)
}

func TestGate_ExternalApproval(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_extern", nil)
	require.NoError(t, err)
	defer g.Close()

	// External approver in a goroutine.
	var sendErr atomic.Value
	go func() {
		// Give Wait a moment to settle. Not strictly necessary because
		// Accept is already running, but makes the test intent clear.
		time.Sleep(50 * time.Millisecond)
		if err := SendDecision("run_extern", DecisionApproved, "ci-pipeline"); err != nil {
			sendErr.Store(err)
		}
	}()

	rec, err := g.Wait(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, DecisionApproved, rec.Decision)
	// Wire-supplied deciders are tagged "external:" on the server side so
	// audit reviewers can see the name came from the (same-uid,
	// unauthenticated) socket rather than a locally-verified approver.
	assert.Equal(t, "external:ci-pipeline", rec.Decider)
	if v := sendErr.Load(); v != nil {
		t.Fatalf("SendDecision failed: %v", v)
	}
}

func TestGate_ExternalDenial(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_extern_deny", nil)
	require.NoError(t, err)
	defer g.Close()

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = SendDecision("run_extern_deny", DecisionDenied, "security-team")
	}()

	rec, err := g.Wait(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDenied))
	assert.Equal(t, "external:security-team", rec.Decider)
}

// Socket perms are the auth boundary; loosening them lets other uids in.
func TestGate_FilesystemPermissions(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_perms", nil)
	require.NoError(t, err)
	defer g.Close()

	info, err := os.Stat(g.sockPath)
	require.NoError(t, err)
	assert.Equalf(t, os.FileMode(0o600), info.Mode().Perm(),
		"socket file must be 0600 (got %o)", info.Mode().Perm())

	parent := filepath.Dir(g.sockPath)
	dinfo, err := os.Stat(parent)
	require.NoError(t, err)
	assert.Equalf(t, os.FileMode(0o700), dinfo.Mode().Perm(),
		"approvals dir must be 0700 (got %o)", dinfo.Mode().Perm())
}

func TestGate_RaceFirstWinsApproved(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_race", nil)
	require.NoError(t, err)
	defer g.Close()

	approver := func(_ []types.PolicyRequirement) (string, error) {
		return "interactive", nil
	}
	rec, err := g.Wait(context.Background(), approver)
	require.NoError(t, err)
	assert.Equal(t, "interactive", rec.Decider)

	// Now try to externally approve — gate has decided, must reject.
	err = SendDecision("run_race", DecisionApproved, "late")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already decided")
}

func TestSendDecision_NoGate(t *testing.T) {
	newTestState(t)
	err := SendDecision("run_does_not_exist", DecisionApproved, "nobody")
	require.Error(t, err)
}

func TestListPending_AliveAndStale(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_alive", nil)
	require.NoError(t, err)
	defer g.Close()

	// Plant a stale socket file by creating one and closing it without
	// keeping a listener.
	sockDir, err := socketPath("run_stale")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(sockDir, []byte("stale"), 0o600))

	pending, err := ListPending()
	require.NoError(t, err)
	assert.Contains(t, pending, "run_alive")
	assert.NotContains(t, pending, "run_stale")

	// Stale file should have been removed.
	_, statErr := os.Stat(sockDir)
	assert.True(t, os.IsNotExist(statErr), "stale socket should have been cleaned up")
}

func TestGate_InvalidRunID(t *testing.T) {
	newTestState(t)
	cases := []string{"", "../etc/passwd", "run/../escape", "run\\with\\backslash"}
	for _, id := range cases {
		_, err := NewGate(id, nil)
		assert.Errorf(t, err, "run id %q should have been rejected", id)
	}
}

func TestGate_ConcurrentProbesDoNotConsume(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_probes", nil)
	require.NoError(t, err)
	defer g.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = ListPending() // each call probes the alive socket
		}()
	}
	wg.Wait()

	// Gate should still be deciding; send the real decision now.
	go func() {
		_ = SendDecision("run_probes", DecisionApproved, "test")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rec, err := g.Wait(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, DecisionApproved, rec.Decision)
}
