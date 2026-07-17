package atls

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// synthIssuer stands in for the per-cloud in-TEE evidence producer: its "report"
// is just bindData ‖ nonce, so a validator that recomputes the same commitment
// accepts it. overrideNonce simulates a report bound to the wrong (stale) nonce.
type synthIssuer struct{ overrideNonce []byte }

func (s *synthIssuer) Issue(_ context.Context, bindData, nonce []byte) ([]byte, error) {
	if s.overrideNonce != nil {
		nonce = s.overrideNonce
	}
	return append(append([]byte(nil), bindData...), nonce...), nil
}

// synthValidator recomputes the expected commitment (bindData ‖ nonce) and checks
// the evidence equals it — the check that is load-bearing for the real verifiers.
type synthValidator struct{ ok bool }

func (v *synthValidator) Validate(_ context.Context, evidence, bindData, nonce []byte) error {
	want := append(append([]byte(nil), bindData...), nonce...)
	if !bytes.Equal(evidence, want) {
		return errMismatch
	}
	v.ok = true
	return nil
}

var errMismatch = &atlsTestErr{"evidence does not commit to this session's bindData+nonce"}

type atlsTestErr struct{ s string }

func (e *atlsTestErr) Error() string { return e.s }

func mustServerCfg(t *testing.T) (*tls.Config, []byte) {
	t.Helper()
	cfg, spki, err := NewServerConfig()
	require.NoError(t, err)
	return cfg, spki
}

// tlsLoopback returns an un-handshaken TLS client/server pair over a real
// localhost TCP connection (so the exporter is real).
func tlsLoopback(t *testing.T, serverCfg, clientCfg *tls.Config) (client, server *tls.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	type res struct {
		c   *tls.Conn
		err error
	}
	sc := make(chan res, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			sc <- res{nil, err}
			return
		}
		sc <- res{tls.Server(raw, serverCfg), nil}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() })
	client = tls.Client(raw, clientCfg)
	r := <-sc
	require.NoError(t, r.err)
	t.Cleanup(func() { r.c.Close() })
	return client, r.c
}

func TestHonestAgentVerifies(t *testing.T) {
	serverCfg, spki := mustServerCfg(t)
	client, server := tlsLoopback(t, serverCfg, NewClientConfig())
	ctx := context.Background()

	errc := make(chan error, 1)
	go func() { errc <- ServerAttest(ctx, server, spki, &synthIssuer{}) }()

	val := &synthValidator{}
	require.NoError(t, ClientAttest(ctx, client, val), "an honest agent must verify")
	require.NoError(t, <-errc)
	require.True(t, val.ok)
}

// TestRelayRejected wires a real MITM: dispatcher → relay(own cert) → genuine
// agent. The relay shuttles the nonce and the agent's evidence, but that evidence
// is bound to the relay↔agent session (agent cert + that exporter), while
// dispatcher recomputes bindData from the relay's cert + the dispatcher↔relay
// exporter — so it rejects.
func TestRelayRejected(t *testing.T) {
	ctx := context.Background()
	agentCfg, agentSPKI := mustServerCfg(t)
	relayCfg, _ := mustServerCfg(t)

	dispConn, relayServer := tlsLoopback(t, relayCfg, NewClientConfig())  // dispatcher ↔ relay
	relayClient, agentConn := tlsLoopback(t, agentCfg, NewClientConfig()) // relay ↔ agent

	go func() { _ = ServerAttest(ctx, agentConn, agentSPKI, &synthIssuer{}) }() // honest agent

	go func() { // relay MITM: read disp nonce → forward to agent → relay evidence back
		if err := relayServer.HandshakeContext(ctx); err != nil {
			return
		}
		nonce, err := readMsg(relayServer, nonceLen)
		if err != nil {
			return
		}
		if err := relayClient.HandshakeContext(ctx); err != nil {
			return
		}
		if err := writeMsg(relayClient, nonce); err != nil {
			return
		}
		ev, err := readMsg(relayClient, maxEvidence)
		if err != nil {
			return
		}
		_ = writeMsg(relayServer, ev)
	}()

	err := ClientAttest(ctx, dispConn, &synthValidator{})
	require.Error(t, err, "evidence relayed from a different session must be rejected")
}

func TestExporterBindingIsLoadBearing(t *testing.T) {
	spki := []byte("agent-cert-spki")
	// Different session exporters MUST yield different bindData — this is what
	// makes relayed evidence (a different session's exporter) fail to verify.
	require.NotEqual(t, bindData(spki, []byte("exporter-A")), bindData(spki, []byte("exporter-B")))
	// And a different cert key MUST yield different bindData — imposter agent.
	require.NotEqual(t, bindData([]byte("keyA"), []byte("x")), bindData([]byte("keyB"), []byte("x")))
	// Stable for identical inputs.
	require.Equal(t, bindData(spki, []byte("x")), bindData(spki, []byte("x")))
}

func TestStaleNonceRejected(t *testing.T) {
	serverCfg, spki := mustServerCfg(t)
	client, server := tlsLoopback(t, serverCfg, NewClientConfig())
	ctx := context.Background()

	stale := bytes.Repeat([]byte{0xAB}, nonceLen)
	go func() { _ = ServerAttest(ctx, server, spki, &synthIssuer{overrideNonce: stale}) }()

	err := ClientAttest(ctx, client, &synthValidator{})
	require.Error(t, err, "evidence bound to a stale nonce must be rejected")
}

func TestClientAttestTimesOutOnStalledPeer(t *testing.T) {
	serverCfg, _ := mustServerCfg(t)
	client, server := tlsLoopback(t, serverCfg, NewClientConfig())

	go func() { // handshake, then stall forever (never sends evidence)
		_ = server.HandshakeContext(context.Background())
		select {}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := ClientAttest(ctx, client, &synthValidator{})
	require.Error(t, err, "a stalled peer must fail fast via the deadline")
	require.Less(t, time.Since(start), 3*time.Second, "must not hang")
}

func swapAttestTimeout(d time.Duration) func() {
	prev := attestPhaseTimeout
	attestPhaseTimeout = d
	return func() { attestPhaseTimeout = prev }
}

// TestClientAttestBoundsWithoutCtxDeadline: a default run (ctx carries no deadline
// because --max-duration was not set) must still fail fast against a peer that
// handshakes then stalls — the pre-verification exchange with an untrusted peer is
// bounded independently of MaxDuration.
func TestClientAttestBoundsWithoutCtxDeadline(t *testing.T) {
	defer swapAttestTimeout(200 * time.Millisecond)()
	serverCfg, _ := mustServerCfg(t)
	client, server := tlsLoopback(t, serverCfg, NewClientConfig())
	go func() { _ = server.HandshakeContext(context.Background()); select {} }()

	start := time.Now()
	err := ClientAttest(context.Background(), client, &synthValidator{})
	require.Error(t, err, "a stalled peer must fail even without a ctx deadline")
	require.Less(t, time.Since(start), 3*time.Second, "must not hang")
}

// TestServerAttestBoundsStalledHandshake: the agent serves with context.Background(),
// so it must still bound a client that connects but never completes the handshake —
// otherwise each stalled connection pins a goroutine forever (DoS).
func TestServerAttestBoundsStalledHandshake(t *testing.T) {
	defer swapAttestTimeout(200 * time.Millisecond)()
	serverCfg, spki := mustServerCfg(t)
	_, server := tlsLoopback(t, serverCfg, NewClientConfig()) // client never handshakes
	start := time.Now()
	err := ServerAttest(context.Background(), server, spki, &synthIssuer{})
	require.Error(t, err, "a client that never handshakes must not pin the agent forever")
	require.Less(t, time.Since(start), 3*time.Second, "must not hang")
}

// TestClientRunAbortsOnCtxCancel: cancelling the run context (Ctrl-C, a MaxDuration
// deadline, or a budget breach) must abort a blocked run-phase read, not hang for
// the whole workload — the confidential-run enforcement path.
func TestClientRunAbortsOnCtxCancel(t *testing.T) {
	serverCfg, spki := mustServerCfg(t)
	client, server := tlsLoopback(t, serverCfg, NewClientConfig())
	go func() { // attest honestly, read the request, then never respond
		if err := ServerAttest(context.Background(), server, spki, &synthIssuer{}); err != nil {
			return
		}
		_, _ = readMsg(server, maxMessage)
		select {}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := ClientRun(ctx, client, &synthValidator{}, []byte("payload"))
	require.Error(t, err, "ctx cancellation must abort the run-phase read")
	require.Less(t, time.Since(start), 3*time.Second, "must not hang past cancellation")
}

func TestExporterIsPerSession(t *testing.T) {
	get := func() []byte {
		serverCfg, _ := mustServerCfg(t)
		client, server := tlsLoopback(t, serverCfg, NewClientConfig())
		go func() { _ = server.HandshakeContext(context.Background()) }()
		require.NoError(t, client.HandshakeContext(context.Background()))
		state := client.ConnectionState()
		e, err := state.ExportKeyingMaterial(exporterLabel, nil, exporterLen)
		require.NoError(t, err)
		return e
	}
	require.NotEqual(t, get(), get(), "each handshake must yield a distinct exporter")
}

func TestSessionRunRoundTrip(t *testing.T) {
	serverCfg, spki := mustServerCfg(t)
	client, server := tlsLoopback(t, serverCfg, NewClientConfig())
	ctx := context.Background()

	handle := func(_ context.Context, req []byte) ([]byte, error) {
		return append([]byte("echo:"), req...), nil
	}
	errc := make(chan error, 1)
	go func() { errc <- ServerRun(ctx, server, spki, &synthIssuer{}, handle) }()

	resp, err := ClientRun(ctx, client, &synthValidator{}, []byte("payload"))
	require.NoError(t, err)
	require.Equal(t, "echo:payload", string(resp))
	require.NoError(t, <-errc)
}

// TestClientRunAbortsWhenAttestationFails proves no secret crosses an unverified
// TEE: a rejecting validator makes ClientRun fail before it sends the request.
func TestClientRunAbortsWhenAttestationFails(t *testing.T) {
	serverCfg, spki := mustServerCfg(t)
	client, server := tlsLoopback(t, serverCfg, NewClientConfig())
	ctx := context.Background()

	delivered := make(chan struct{}, 1)
	handle := func(_ context.Context, _ []byte) ([]byte, error) { delivered <- struct{}{}; return nil, nil }
	// Stale-nonce issuer -> the validator rejects, so attestation fails.
	go func() {
		_ = ServerRun(ctx, server, spki, &synthIssuer{overrideNonce: bytes.Repeat([]byte{1}, nonceLen)}, handle)
	}()

	_, err := ClientRun(ctx, client, &synthValidator{}, []byte("secret-payload"))
	require.Error(t, err, "ClientRun must fail when attestation fails")
	select {
	case <-delivered:
		t.Fatal("payload was delivered despite failed attestation")
	default:
	}
}
