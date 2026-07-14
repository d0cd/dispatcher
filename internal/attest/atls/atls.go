// Package atls is a SPIKE — it is NOT wired into the confidential run path. It
// sizes an attested-TLS (aTLS) agent channel that closes the "first sealed
// payload wins" gap found in the audit: the workload payload would ride a single
// TLS session cryptographically bound to the attestation, so a co-located or
// on-path host can't preempt the run, and the per-run firewall stops being the
// only boundary.
//
// It is CLEAN-ROOM. Edgeless's reference atls (Constellation/Contrast) is an
// internal/, BUSL-1.1 package and can neither be imported nor copied; this
// mirrors only its Issuer/Validator *shape*, which is the standard aTLS pattern,
// on top of the Go standard library (no new dependencies).
//
// Freshness/session binding: stdlib crypto/tls does not expose the handshake
// randoms, so instead of a cert-embedded quote we bind evidence to the session
// via RFC 5705 exported keying material (tls.ConnectionState.ExportKeyingMaterial)
// plus the peer cert's public key and a verifier-chosen nonce. Evidence verified
// on one session therefore can't be replayed onto another (anti-relay), and only
// the party that completed *this* handshake can present matching evidence.
package atls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// exporterLabel is the RFC 5705 label the session-binding value is derived under.
const exporterLabel = "dispatcher/confidential/atls/v1"

// defaultExchangeTimeout bounds the post-handshake nonce/evidence exchange when
// the caller's context carries no deadline, so a stalled peer can't hang the
// goroutine indefinitely (the socket is otherwise read with blocking io.ReadFull).
const defaultExchangeTimeout = 30 * time.Second

// applyDeadline sets an absolute I/O deadline on conn for the exchange — the
// caller's ctx deadline if present, else defaultExchangeTimeout — and returns a
// func that clears it. This makes the advertised ctx cancellation actually govern
// the peer I/O, not just the attestation computation.
func applyDeadline(ctx context.Context, conn *tls.Conn) func() {
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(defaultExchangeTimeout)
	}
	_ = conn.SetDeadline(dl)
	return func() { _ = conn.SetDeadline(time.Time{}) }
}

// Issuer runs inside the TEE. Given bindData (a hash over the agent's TLS public
// key and the session exporter) and the verifier's per-run nonce, it returns
// attestation evidence whose REPORT_DATA commits to both. In production this is
// backed by the in-TEE producers (agent.Serve + the per-cloud AttestFunc in
// internal/attest/agent/{aws,azure,nitro}), which generate the SNP report / MAA
// token / Nitro COSE doc with REPORT_DATA = H(nonce ‖ bindData). (agent.FetchAttestation
// is the dispatcher-side fetch that ClientAttest below replaces, not a producer.)
type Issuer interface {
	Issue(ctx context.Context, bindData, nonce []byte) (evidence []byte, err error)
}

// Validator runs in dispatcher. It verifies evidence (chain + measurement pins,
// exactly today's per-cloud attest.Attester core) AND that the evidence's
// REPORT_DATA commits to the expected bindData and nonce. In production this
// wraps the existing verifiers behind internal/attest.
type Validator interface {
	Validate(ctx context.Context, evidence, bindData, nonce []byte) error
}

// bindData binds a TLS cert public key to the session exporter: the attested
// evidence proves "this key, on this session", not just "some genuine TEE".
func bindData(certPub, exporter []byte) []byte {
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, uint32(len(certPub)))
	h.Write(certPub)
	h.Write(exporter)
	return h.Sum(nil)
}

func exporter(cs tls.ConnectionState) ([]byte, error) {
	// The TLS 1.3 requirement is enforced by MinVersion in ServerConfig/ClientConfig
	// (ExportKeyingMaterial itself only refuses active renegotiation / a session
	// with neither TLS 1.3 nor Extended Master Secret). EKM here just derives the
	// per-session binding material.
	return cs.ExportKeyingMaterial(exporterLabel, nil, 32)
}

func pubDER(cert *x509.Certificate) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(cert.PublicKey)
}

// ServerConfig is the in-TEE agent's TLS config. cert MUST be the agent's
// ephemeral, attestation-bound key. There is no client auth: the client
// authenticates the server via attestation (ClientAttest), not PKI.
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
}

// ClientConfig is dispatcher's TLS config. PKI verification is disabled because
// trust is established by attestation over the session (ClientAttest), not a CA.
func ClientConfig() *tls.Config {
	// #nosec G402 -- trust is established by attestation binding, not PKI.
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
}

// ServerAttest runs on the agent AFTER the handshake: read the client's nonce,
// bind the agent's own cert key + this session's exporter, issue evidence, and
// send it. leafPub is the DER of the agent cert's public key (the key it serves).
func ServerAttest(ctx context.Context, conn *tls.Conn, issuer Issuer, leafPub []byte) error {
	defer applyDeadline(ctx, conn)()
	exp, err := exporter(conn.ConnectionState())
	if err != nil {
		return fmt.Errorf("atls server: session exporter: %w", err)
	}
	nonce, err := readFrame(conn)
	if err != nil {
		return fmt.Errorf("atls server: read nonce: %w", err)
	}
	evidence, err := issuer.Issue(ctx, bindData(leafPub, exp), nonce)
	if err != nil {
		return fmt.Errorf("atls server: issue evidence: %w", err)
	}
	return writeFrame(conn, evidence)
}

// ClientAttest runs on dispatcher AFTER the handshake: send a fresh nonce, read
// the agent's evidence, and validate it against the exact server cert public key
// seen on THIS session and this session's exporter. Returns nil only when the
// evidence is genuine, measurement-pinned, and bound to this session — after
// which the caller may deliver the sealed workload over the same conn.
func ClientAttest(ctx context.Context, conn *tls.Conn, v Validator, nonce []byte) error {
	defer applyDeadline(ctx, conn)()
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("atls client: server presented no certificate")
	}
	exp, err := exporter(cs)
	if err != nil {
		return fmt.Errorf("atls client: session exporter: %w", err)
	}
	leafPub, err := pubDER(cs.PeerCertificates[0])
	if err != nil {
		return fmt.Errorf("atls client: marshal server key: %w", err)
	}
	if err := writeFrame(conn, nonce); err != nil {
		return fmt.Errorf("atls client: send nonce: %w", err)
	}
	evidence, err := readFrame(conn)
	if err != nil {
		return fmt.Errorf("atls client: read evidence: %w", err)
	}
	return v.Validate(ctx, evidence, bindData(leafPub, exp), nonce)
}

// LeafPub extracts the DER public key from a served tls.Certificate for
// ServerAttest.
func LeafPub(cert tls.Certificate) ([]byte, error) {
	if cert.Leaf != nil {
		return pubDER(cert.Leaf)
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("atls: certificate has no leaf")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return pubDER(leaf)
}

// Length-prefixed framing (u32 big-endian) — a minimal, self-delimiting wire for
// the post-handshake nonce/evidence exchange over the TLS conn.

const maxFrame = 1 << 20 // 1 MiB — evidence is a report/token, never large.

func writeFrame(w io.Writer, b []byte) error {
	if len(b) > maxFrame {
		return fmt.Errorf("atls: frame too large (%d)", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, fmt.Errorf("atls: frame too large (%d)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
