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
