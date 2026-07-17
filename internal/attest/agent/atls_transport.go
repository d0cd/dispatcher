package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"

	"github.com/d0cd/dispatcher/internal/attest/atls"
)

// ServeATLS is the aTLS replacement for Serve: for each accepted connection it
// completes the attestation exchange (evidence bound to the TLS session, not a
// handed-out channel key), then runs the delivered payload and returns the result
// over the same attested, encrypted session — no HPKE sealing on this path. The
// listener is a seam (TCP, or vsock for a Nitro enclave); TLS runs over any of them.
func ServeATLS(l net.Listener, cfg *tls.Config, certSPKI []byte, attest AttestFunc, runner func(ctx context.Context, p Payload) Result) error {
	if runner == nil {
		runner = defaultRunner
	}
	issuer := IssuerFromAttest(attest)
	// Cap concurrent connections: the only access control is the per-run firewall
	// (aTLS attests the server, not the client), so bound the goroutines any peer
	// within that CIDR can spawn rather than accepting unboundedly.
	sem := make(chan struct{}, maxConcurrentATLSConns)
	for {
		raw, err := l.Accept()
		if err != nil {
			return err
		}
		sem <- struct{}{}
		go func(c net.Conn) {
			defer func() { <-sem }()
			serveATLSConn(tls.Server(c, cfg), certSPKI, issuer, runner)
		}(raw)
	}
}

// maxConcurrentATLSConns bounds in-flight aTLS connections the agent serves at
// once. Dispatcher drives one run per agent, so this is generous headroom while
// still capping a flood from any peer inside the firewall CIDR.
const maxConcurrentATLSConns = 16

// serveATLSConn handles one connection: attest, then run one payload and return
// its result. A failed attestation delivers nothing (atls.ServerRun aborts before
// reading the payload).
func serveATLSConn(conn *tls.Conn, certSPKI []byte, issuer atls.Issuer, runner func(ctx context.Context, p Payload) Result) {
	defer conn.Close()
	// The run may take arbitrarily long, so the run phase is served under
	// context.Background(); the attest phase bounds itself with its own deadline
	// inside atls.ServerAttest (independent of ctx), so a stalled handshake can't
	// pin this goroutine.
	_ = atls.ServerRun(context.Background(), conn, certSPKI, issuer, func(ctx context.Context, request []byte) ([]byte, error) {
		var p Payload
		if err := json.Unmarshal(request, &p); err != nil {
			return nil, fmt.Errorf("parse payload: %w", err)
		}
		res := runner(ctx, p)
		return json.Marshal(res)
	})
}

// ServeATLSOn generates a fresh server TLS config (ephemeral key) and serves the
// aTLS confidential exchange on l with the default exec runner. A Nitro enclave
// uses this directly over its vsock listener; RunServerATLS wraps it for TCP.
func ServeATLSOn(l net.Listener, attest AttestFunc) error {
	cfg, spki, err := atls.NewServerConfig()
	if err != nil {
		return err
	}
	return ServeATLS(l, cfg, spki, attest, defaultRunner)
}

// RunServerATLS serves the aTLS confidential exchange on a TCP addr. It is the
// aTLS replacement for RunServer, used by the per-cloud agent binaries.
func RunServerATLS(addr string, attest AttestFunc) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ServeATLSOn(l, attest)
}

// RunOverATLS is the dispatcher-side aTLS transport: dial the agent, verify it via
// validator (the per-cloud attestation), then deliver payload and return the
// result — all over the attested session. Nothing is sent until the peer verifies
// as a genuine, measurement-pinned TEE bound to this session.
func RunOverATLS(ctx context.Context, addr string, validator atls.Validator, payload Payload) (Result, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, fmt.Errorf("dial agent: %w", err)
	}
	conn := tls.Client(raw, atls.NewClientConfig())
	defer conn.Close()

	request, err := json.Marshal(payload)
	if err != nil {
		return Result{}, err
	}
	response, err := atls.ClientRun(ctx, conn, validator, request)
	if err != nil {
		return Result{}, err
	}
	var res Result
	if err := json.Unmarshal(response, &res); err != nil {
		return Result{}, fmt.Errorf("parse result: %w", err)
	}
	return res, nil
}

// AttestOverATLS dials the agent and runs ONLY the attestation phase, validating
// the peer via validator — no payload is delivered and nothing runs. It is the
// capture-time counterpart to RunOverATLS: derive a measured image's pinned value
// from a booted TEE without executing a workload.
func AttestOverATLS(ctx context.Context, addr string, validator atls.Validator) error {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial agent: %w", err)
	}
	conn := tls.Client(raw, atls.NewClientConfig())
	defer conn.Close()
	return atls.ClientAttest(ctx, conn, validator)
}
