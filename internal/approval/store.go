// Package approval gates policy-requiring runs on an operator decision.
// Each run opens a per-run Unix socket; in-process and external approvers
// race for it. Filesystem perms (0700 dir, 0600 socket, owner-only) are
// the auth boundary. The decision Record is embedded in the run state by
// the executor — no separate persisted approval state.
package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// Decision is the resolution of an approval request. There is no "pending"
// state — pending exists only as "Gate.Wait has not yet returned".
type Decision string

const (
	DecisionApproved Decision = "approved"
	DecisionDenied   Decision = "denied"
)

// Record is the audit-trail shape of an approval decision.
type Record struct {
	RunID        string                    `json:"runId"`
	Requirements []types.PolicyRequirement `json:"requirements"`
	RequestedAt  time.Time                 `json:"requestedAt"`
	DecidedAt    time.Time                 `json:"decidedAt"`
	Decision     Decision                  `json:"decision"`
	Decider      string                    `json:"decider"`
}

// ApprovalFunc is an in-process approver. Returns the decider string
// (audit-distinct: "interactive:<user>", "yes-flag:<user>", "ci:<job>")
// and either nil (approve) or ErrDenied (deny).
type ApprovalFunc func(reqs []types.PolicyRequirement) (decider string, err error)

var ErrDenied = errors.New("approval denied")

func validateRunID(id string) error {
	if id == "" {
		return fmt.Errorf("run id is empty")
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid run id %q: contains path separator or traversal", id)
	}
	return nil
}

func socketPath(runID string) (string, error) {
	if err := validateRunID(runID); err != nil {
		return "", err
	}
	dir, err := state.Subdir("approvals")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, runID+".sock"), nil
}

// Wire protocol: one wireMsg in, one wireReply out, connection closes.
type wireMsg struct {
	Action   string   `json:"action"` // "decide" or "ping"
	Decision Decision `json:"decision,omitempty"`
	Decider  string   `json:"decider,omitempty"`
}

type wireReply struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Gate is single-shot: `done` CAS-flips on the first valid decision; the
// loser (in-process or external) is rejected with "already decided".
type Gate struct {
	runID    string
	reqs     []types.PolicyRequirement
	sockPath string
	listener net.Listener

	once    sync.Once
	done    atomic.Bool
	decided chan decisionMsg
	closed  chan struct{}
}

type decisionMsg struct {
	decision Decision
	decider  string
}

// umaskMu serializes syscall.Umask (process-wide) across concurrent NewGate.
var umaskMu sync.Mutex

// NewGate opens the per-run socket. Removes any stale socket from a
// crashed predecessor; the 0700 parent dir prevents path hijack.
func NewGate(runID string, reqs []types.PolicyRequirement) (*Gate, error) {
	sock, err := socketPath(runID)
	if err != nil {
		return nil, err
	}
	_ = os.Remove(sock)

	umaskMu.Lock()
	oldMask := syscall.Umask(0o177)
	l, err := net.Listen("unix", sock)
	syscall.Umask(oldMask)
	umaskMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("listen approval socket: %w", err)
	}
	_ = os.Chmod(sock, 0o600) // some BSDs ignore umask for unix sockets

	g := &Gate{
		runID:    runID,
		reqs:     reqs,
		sockPath: sock,
		listener: l,
		decided:  make(chan decisionMsg, 1),
		closed:   make(chan struct{}),
	}
	go g.serve()
	return g, nil
}

// Close removes the socket file and unblocks the accept loop. Idempotent.
func (g *Gate) Close() error {
	var err error
	g.once.Do(func() {
		close(g.closed)
		err = g.listener.Close()
		_ = os.Remove(g.sockPath)
	})
	return err
}

// Wait blocks until a decision arrives (in-process or external) or ctx
// is canceled. Returns ErrDenied alongside the Record when denied.
func (g *Gate) Wait(ctx context.Context, inProcess ApprovalFunc) (Record, error) {
	rec := Record{
		RunID:        g.runID,
		Requirements: g.reqs,
		RequestedAt:  time.Now().UTC(),
	}

	if inProcess != nil {
		go func() {
			decider, err := inProcess(g.reqs)
			var d decisionMsg
			if errors.Is(err, ErrDenied) {
				d = decisionMsg{decision: DecisionDenied, decider: decider}
			} else if err != nil {
				d = decisionMsg{decision: DecisionDenied, decider: fmt.Sprintf("approver-error:%v", err)}
			} else {
				d = decisionMsg{decision: DecisionApproved, decider: decider}
			}
			if !g.done.CompareAndSwap(false, true) {
				return // external decider won the race
			}
			select {
			case g.decided <- d:
			case <-g.closed:
			}
		}()
	}

	select {
	case <-ctx.Done():
		return rec, ctx.Err()
	case d := <-g.decided:
		rec.DecidedAt = time.Now().UTC()
		rec.Decision = d.decision
		rec.Decider = d.decider
		if d.decision == DecisionDenied {
			return rec, ErrDenied
		}
		return rec, nil
	}
}

// serve runs the accept loop. Each connection is handled in its own
// goroutine so a slow client can't block other probes.
func (g *Gate) serve() {
	for {
		conn, err := g.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go g.handleConn(conn)
	}
}

func (g *Gate) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var msg wireMsg
	if err := json.NewDecoder(conn).Decode(&msg); err != nil {
		return // probe (dial + immediate close) lands here as EOF
	}

	switch msg.Action {
	case "ping":
		_ = json.NewEncoder(conn).Encode(wireReply{Status: "ok"})
		return
	case "decide", "":
		if msg.Decision != DecisionApproved && msg.Decision != DecisionDenied {
			_ = json.NewEncoder(conn).Encode(wireReply{
				Status: "error",
				Reason: fmt.Sprintf("invalid decision %q", msg.Decision),
			})
			return
		}
		if !g.done.CompareAndSwap(false, true) {
			_ = json.NewEncoder(conn).Encode(wireReply{
				Status: "error",
				Reason: "already decided",
			})
			return
		}
		// "external:" prefix tells audit reviewers the name came over the
		// socket — same-uid wire input, not a locally-verified approver.
		decider := msg.Decider
		if !strings.HasPrefix(decider, "external:") {
			decider = "external:" + decider
		}
		select {
		case g.decided <- decisionMsg{decision: msg.Decision, decider: decider}:
			_ = json.NewEncoder(conn).Encode(wireReply{Status: "ok"})
		case <-g.closed:
			_ = json.NewEncoder(conn).Encode(wireReply{Status: "error", Reason: "gate closed"})
		}
	default:
		_ = json.NewEncoder(conn).Encode(wireReply{
			Status: "error",
			Reason: fmt.Sprintf("unknown action %q", msg.Action),
		})
	}
}

// SendDecision delivers a decision to a running dispatcher's approval gate.
func SendDecision(runID string, decision Decision, decider string) error {
	sock, err := socketPath(runID)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to approval gate for %s: %w", runID, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := json.NewEncoder(conn).Encode(wireMsg{
		Action:   "decide",
		Decision: decision,
		Decider:  decider,
	}); err != nil {
		return fmt.Errorf("send decision: %w", err)
	}
	var reply wireReply
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		return fmt.Errorf("read ack: %w", err)
	}
	if reply.Status != "ok" {
		return fmt.Errorf("gate rejected decision: %s", reply.Reason)
	}
	return nil
}

// ListPending returns run IDs with an open approval gate. Stale sockets
// from crashed runs are cleaned up as a side effect.
func ListPending() ([]string, error) {
	dir, err := state.Subdir("approvals")
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var alive []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sock") {
			continue
		}
		sock := filepath.Join(dir, e.Name())
		info, statErr := os.Lstat(sock)
		if statErr != nil {
			continue
		}
		// Non-socket leftovers (regular files, editor backups) would shadow
		// a future run reusing the id. Clear them.
		if info.Mode().Type()&os.ModeSocket == 0 {
			_ = os.Remove(sock)
			continue
		}

		conn, err := net.DialTimeout("unix", sock, 200*time.Millisecond)
		if err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				_ = os.Remove(sock) // socket file with no listener = crashed
			}
			continue
		}
		// Ping rather than blank-Close so the gate's server doesn't see EOF
		// and treat a probe as a malformed decide.
		_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
		if err := json.NewEncoder(conn).Encode(wireMsg{Action: "ping"}); err == nil {
			var reply wireReply
			_ = json.NewDecoder(conn).Decode(&reply)
		}
		conn.Close()
		alive = append(alive, strings.TrimSuffix(e.Name(), ".sock"))
	}
	return alive, nil
}
