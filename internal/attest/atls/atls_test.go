package atls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeIssuer/fakeValidator stand in for the real per-cloud evidence producer and
// verifier. "Evidence" is an HMAC over the binding — honest issuers bind exactly
// (bindData, nonce); the failure modes model an agent that can't actually bind to
// THIS session/key (a relay/attacker) or ignores the fresh nonce (a replay).
type fakeAttest struct {
	key         []byte
	ignoreBind  bool // issue evidence bound to zeros instead of the real bindData
	ignoreNonce bool // issue evidence that omits the fresh nonce
}

func (f *fakeAttest) Issue(_ context.Context, bindData, nonce []byte) ([]byte, error) {
	b, n := bindData, nonce
	if f.ignoreBind {
		b = make([]byte, len(bindData))
	}
	if f.ignoreNonce {
		n = nil
	}
	return f.mac(b, n), nil
}

func (f *fakeAttest) Validate(_ context.Context, evidence, bindData, nonce []byte) error {
	if !hmac.Equal(evidence, f.mac(bindData, nonce)) {
		return assertErr("evidence not bound to this session/key/nonce")
	}
	return nil
}

func (f *fakeAttest) mac(bindData, nonce []byte) []byte {
	m := hmac.New(sha256.New, f.key)
	m.Write(bindData)
	m.Write(nonce)
	return m.Sum(nil)
}

type assertErr string

func (e assertErr) Error() string { return string(e) }

// runExchange stands up a real loopback TLS 1.3 session and runs the aTLS
// attestation exchange over it, returning the client-side verdict.
func runExchange(t *testing.T, issuer Issuer, validator Validator) error {
	t.Helper()
	cert := selfSignedCert(t)
	leafPub, err := LeafPub(cert)
	require.NoError(t, err)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", ServerConfig(cert))
	require.NoError(t, err)
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			srvErr <- aerr
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if herr := tc.HandshakeContext(ctx); herr != nil {
			srvErr <- herr
			return
		}
		srvErr <- ServerAttest(ctx, tc, issuer, leafPub)
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), ClientConfig())
	require.NoError(t, err)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, client.HandshakeContext(ctx))

	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	verdict := ClientAttest(ctx, client, validator, nonce)
	require.NoError(t, <-srvErr, "server side of the exchange")
	return verdict
}

// Happy path: an honest agent that binds to this session's key+exporter+nonce
// verifies, so the caller may deliver the sealed payload over the same session.
func TestATLS_HonestAgentVerifies(t *testing.T) {
	f := &fakeAttest{key: []byte("shared-attest-key")}
	require.NoError(t, runExchange(t, f, f))
}

// A relay / co-located attacker that can't bind evidence to THIS TLS session
// (wrong key+exporter) is rejected — this is the property the "first payload
// wins" gap lacked.
func TestATLS_UnboundEvidenceRejected(t *testing.T) {
	issuer := &fakeAttest{key: []byte("k"), ignoreBind: true}
	validator := &fakeAttest{key: []byte("k")}
	err := runExchange(t, issuer, validator)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bound to this session")
}

// A replayed report that omits the verifier's fresh nonce is rejected.
func TestATLS_StaleNonceRejected(t *testing.T) {
	issuer := &fakeAttest{key: []byte("k"), ignoreNonce: true}
	validator := &fakeAttest{key: []byte("k")}
	require.Error(t, runExchange(t, issuer, validator))
}

// Each handshake yields a distinct exporter, so evidence verified on one session
// cannot be replayed onto another (anti-relay), even for the same server key.
func TestATLS_ExporterIsPerSession(t *testing.T) {
	cert := selfSignedCert(t)
	e1 := clientExporterFromOneHandshake(t, cert)
	e2 := clientExporterFromOneHandshake(t, cert)
	assert.NotEqual(t, e1, e2, "exporter must differ per TLS session")
}

func clientExporterFromOneHandshake(t *testing.T, cert tls.Certificate) []byte {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ServerConfig(cert))
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		if conn, aerr := ln.Accept(); aerr == nil {
			_ = conn.(*tls.Conn).Handshake()
			time.Sleep(50 * time.Millisecond)
			conn.Close()
		}
	}()
	client, err := tls.Dial("tcp", ln.Addr().String(), ClientConfig())
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.Handshake())
	exp, err := exporter(client.ConnectionState())
	require.NoError(t, err)
	return exp
}

// TestATLS_RelayRejected is the real anti-relay proof: a relay terminates TLS to
// dispatcher with its OWN cert and proxies the app frames to a genuine agent. The
// agent binds evidence to (agentCertKey ‖ agent<->relay exporter); dispatcher
// validates against (relayCertKey ‖ dispatcher<->relay exporter) — both differ, so
// even genuine, freshly-nonced evidence relayed onto the wrong session is rejected.
func TestATLS_RelayRejected(t *testing.T) {
	honest := &fakeAttest{key: []byte("genuine-tee-hmac-key")}

	agentCert := selfSignedCert(t)
	agentLeafPub, err := LeafPub(agentCert)
	require.NoError(t, err)
	agentLn, err := tls.Listen("tcp", "127.0.0.1:0", ServerConfig(agentCert))
	require.NoError(t, err)
	defer agentLn.Close()
	go func() {
		conn, aerr := agentLn.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		if tc.Handshake() == nil {
			_ = ServerAttest(context.Background(), tc, honest, agentLeafPub)
		}
	}()

	relayCert := selfSignedCert(t) // the relay's own key — NOT the agent's
	relayLn, err := tls.Listen("tcp", "127.0.0.1:0", ServerConfig(relayCert))
	require.NoError(t, err)
	defer relayLn.Close()
	go func() {
		down, aerr := relayLn.Accept() // dispatcher <-> relay
		if aerr != nil {
			return
		}
		defer down.Close()
		dtc := down.(*tls.Conn)
		if dtc.Handshake() != nil {
			return
		}
		up, derr := tls.Dial("tcp", agentLn.Addr().String(), ClientConfig()) // relay <-> agent
		if derr != nil {
			return
		}
		defer up.Close()
		if up.Handshake() != nil {
			return
		}
		// Proxy the two application frames verbatim.
		if nonce, ferr := readFrame(dtc); ferr == nil {
			_ = writeFrame(up, nonce)
		}
		if ev, ferr := readFrame(up); ferr == nil {
			_ = writeFrame(dtc, ev)
		}
	}()

	client, err := tls.Dial("tcp", relayLn.Addr().String(), ClientConfig())
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.Handshake())
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	err = ClientAttest(context.Background(), client, honest, nonce)
	require.Error(t, err, "relayed evidence is bound to the agent<->relay session, not dispatcher's — must reject")
}

// The session exporter must be load-bearing in the binding: the SAME cert key and
// nonce, but a different session exporter, must fail — so a regression that
// dropped the exporter from bindData (H(certPub) only) would fail this test.
func TestATLS_ExporterBindingIsLoadBearing(t *testing.T) {
	ctx := context.Background()
	f := &fakeAttest{key: []byte("k")}
	pub := []byte("agent-cert-pubkey")
	expA := make([]byte, 32)
	expB := make([]byte, 32)
	expB[0] = 1 // a different session
	nonce := []byte("run-nonce")

	ev, err := f.Issue(ctx, bindData(pub, expA), nonce)
	require.NoError(t, err)
	require.NoError(t, f.Validate(ctx, ev, bindData(pub, expA), nonce), "same session must validate")
	require.Error(t, f.Validate(ctx, ev, bindData(pub, expB), nonce), "different session exporter must reject")
}

// A peer that completes the handshake then stalls must not hang ClientAttest —
// the deadline (from ctx) makes it fail fast.
func TestATLS_ClientAttestTimesOutOnStalledPeer(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ServerConfig(cert))
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		_ = tc.Handshake()
		_, _ = readFrame(tc) // read the nonce, then withhold evidence
		time.Sleep(2 * time.Second)
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), ClientConfig())
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.Handshake())

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = ClientAttest(ctx, client, &fakeAttest{key: []byte("k")}, make([]byte, 32))
	require.Error(t, err, "a stalled peer must fail via deadline")
	require.Less(t, time.Since(start), 1500*time.Millisecond, "must fail fast, not hang until the peer closes")
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dispatcher-attest-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return cert
}
