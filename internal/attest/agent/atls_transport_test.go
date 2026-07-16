package agent

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest/atls"
)

// synthValidator accepts evidence that equals bindData ‖ nonce (what synthAttest
// below produces) — the atls binding round-trip is proven in the atls package; here
// we prove the agent-side transport (attest → run payload → return result).
type synthValidator struct{}

func (synthValidator) Validate(_ context.Context, evidence, bindData, nonce []byte) error {
	want := append(append([]byte(nil), bindData...), nonce...)
	if !bytes.Equal(evidence, want) {
		return context.Canceled // any error
	}
	return nil
}

func synthAttest(_ context.Context, nonce, bindData []byte) (string, error) {
	return string(append(append([]byte(nil), bindData...), nonce...)), nil
}

// TestServeATLS_EndToEnd runs a full confidential exchange over aTLS with the real
// agent server transport: dispatcher verifies the agent, delivers a payload, the
// agent runs it, and the result comes back over the attested session.
func TestServeATLS_EndToEnd(t *testing.T) {
	cfg, spki, err := atls.NewServerConfig()
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	runner := func(_ context.Context, p Payload) Result {
		return Result{ExitCode: 0, Stdout: []byte("ran: " + strings.Join(p.Command, " "))}
	}
	go func() { _ = ServeATLS(ln, cfg, spki, synthAttest, runner) }()

	res, err := RunOverATLS(context.Background(), ln.Addr().String(), synthValidator{}, Payload{Command: []string{"echo", "hi"}})
	require.NoError(t, err)
	require.Equal(t, 0, res.ExitCode)
	require.Equal(t, "ran: echo hi", string(res.Stdout))
}

// TestRunOverATLS_RejectsUnverifiedAgent proves nothing is delivered to an agent
// that fails verification (the validator rejects → RunOverATLS errors, no payload).
func TestRunOverATLS_RejectsUnverifiedAgent(t *testing.T) {
	cfg, spki, err := atls.NewServerConfig()
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	ran := make(chan struct{}, 1)
	runner := func(_ context.Context, _ Payload) Result { ran <- struct{}{}; return Result{} }
	go func() { _ = ServeATLS(ln, cfg, spki, synthAttest, runner) }()

	// A validator that always rejects.
	_, err = RunOverATLS(context.Background(), ln.Addr().String(), rejectValidator{}, Payload{Command: []string{"echo"}})
	require.Error(t, err, "an agent that fails verification must not receive the payload")
	select {
	case <-ran:
		t.Fatal("workload ran despite failed verification")
	default:
	}
}

type rejectValidator struct{}

func (rejectValidator) Validate(context.Context, []byte, []byte, []byte) error {
	return context.Canceled
}

// capturingValidator records the attested evidence — the shape a measurement
// capture uses to derive a pin from a booted TEE without running a workload.
type capturingValidator struct{ evidence []byte }

func (c *capturingValidator) Validate(_ context.Context, evidence, bindData, nonce []byte) error {
	want := append(append([]byte(nil), bindData...), nonce...)
	if !bytes.Equal(evidence, want) {
		return context.Canceled
	}
	c.evidence = evidence
	return nil
}

// TestAttestOverATLS_CapturesEvidence proves the attest-only client path completes
// the binding exchange and hands the validator the session-bound evidence, without
// delivering a payload or running anything.
func TestAttestOverATLS_CapturesEvidence(t *testing.T) {
	cfg, spki, err := atls.NewServerConfig()
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	ran := make(chan struct{}, 1)
	runner := func(context.Context, Payload) Result { ran <- struct{}{}; return Result{} }
	go func() { _ = ServeATLS(ln, cfg, spki, synthAttest, runner) }()

	capture := &capturingValidator{}
	require.NoError(t, AttestOverATLS(context.Background(), ln.Addr().String(), capture))
	require.NotEmpty(t, capture.evidence, "the validator must receive the session-bound evidence")
	select {
	case <-ran:
		t.Fatal("attest-only path must not run a workload")
	default:
	}
}
