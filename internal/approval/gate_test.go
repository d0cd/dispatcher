package approval

import (
	"context"
	"encoding/json"
	"errors"
	"net"
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

// After Wait consumes an approval and the run proceeds, a late `approve --deny`
// can't stop it, so the gate must refuse the decision ("already decided") rather
// than accept it, ack "ok", and silently discard it.
func TestGate_LateDenyRefusedAfterApproval(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_late", []types.PolicyRequirement{{Name: "x"}})
	require.NoError(t, err)
	defer g.Close()

	rec, err := g.Wait(context.Background(), func([]types.PolicyRequirement) (string, error) { return "me", nil })
	require.NoError(t, err)
	require.Equal(t, DecisionApproved, rec.Decision)

	accepted := g.settle(decisionMsg{decision: DecisionDenied, decider: "late"})
	assert.False(t, accepted, "a late deny after the run was approved must be refused, not accepted-and-discarded")
}

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

// A non-ErrDenied approver error must fail closed as a Denied decision, tagged
// so audit shows it came from an approver fault (not an explicit deny).
func TestGate_InProcessApproverErrorDenies(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_apperr", nil)
	require.NoError(t, err)
	defer g.Close()

	approver := func(_ []types.PolicyRequirement) (string, error) {
		return "carol", errors.New("boom")
	}

	rec, err := g.Wait(context.Background(), approver)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDenied), "an approver fault must fail closed as Denied")
	assert.Equal(t, DecisionDenied, rec.Decision)
	assert.Contains(t, rec.Decider, "approver-error:")
}

// A canceled context must abandon the wait with the context error and no
// recorded decision (operator never responded / Ctrl-C).
func TestGate_ContextCancelReturnsError(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_ctx", nil)
	require.NoError(t, err)
	defer g.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()

	rec, err := g.Wait(ctx, nil) // no approver, no external decision
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
	assert.Equal(t, Decision(""), rec.Decision, "no decision must be recorded on cancel")
}

// A denial takes precedence over an approval already recorded on the gate, so a
// racing approve can't flip an explicit deny to approved (fail closed).
func TestGate_DenyOverridesRecordedApproval(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_denyprec", nil)
	require.NoError(t, err)
	defer g.Close()

	require.True(t, g.settle(decisionMsg{decision: DecisionApproved, decider: "a"}))
	// A subsequent denial is accepted (overrides), and the settled result is deny.
	require.True(t, g.settle(decisionMsg{decision: DecisionDenied, decider: "b"}))
	g.mu.Lock()
	got := g.result.decision
	g.mu.Unlock()
	assert.Equal(t, DecisionDenied, got)
	// A further approval can no longer flip it.
	assert.False(t, g.settle(decisionMsg{decision: DecisionApproved, decider: "c"}))
}

// After Wait returns on ctx cancellation, a late external decision must be
// refused rather than acked 'ok' for an abandoned run.
func TestGate_AbandonedGateRefusesLateDecision(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_abandon", nil)
	require.NoError(t, err)
	defer g.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = g.Wait(ctx, nil)
	require.Error(t, err)

	// The gate is abandoned; an external decision is rejected.
	err = SendDecision("run_abandon", DecisionApproved, "late")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already decided")
}

// A wire decision with no decider is attributed to "external:unknown", never a
// nameless "external:".
func TestGate_EmptyDeciderRecordedAsUnknown(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_nodecider", nil)
	require.NoError(t, err)
	defer g.Close()

	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = SendDecision("run_nodecider", DecisionApproved, "")
	}()
	rec, err := g.Wait(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "external:unknown", rec.Decider)
}

// An invalid decision on the wire must be rejected before the single-shot CAS,
// so it doesn't consume the gate — a subsequent valid decision still wins.
func TestGate_InvalidDecisionDoesNotConsumeGate(t *testing.T) {
	newTestState(t)
	g, err := NewGate("run_baddec", nil)
	require.NoError(t, err)
	defer g.Close()

	sock, err := socketPath("run_baddec")
	require.NoError(t, err)
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	require.NoError(t, err)
	require.NoError(t, json.NewEncoder(conn).Encode(wireMsg{
		Action: "decide", Decision: Decision("maybe"), Decider: "x",
	}))
	var reply wireReply
	require.NoError(t, json.NewDecoder(conn).Decode(&reply))
	conn.Close()
	assert.Equal(t, "error", reply.Status)
	assert.Contains(t, reply.Reason, "invalid decision")

	// Gate must still be open: a valid decision now wins.
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = SendDecision("run_baddec", DecisionApproved, "ci")
	}()
	rec, err := g.Wait(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, DecisionApproved, rec.Decision)
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
