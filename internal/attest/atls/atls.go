// Package atls implements a clean-room attested-TLS channel for the confidential
// agent<->dispatcher exchange, on the Go standard library (no new dependency).
//
// The in-TEE agent serves TLS 1.3 with a fresh ephemeral key as its certificate;
// dispatcher dials with InsecureSkipVerify (trust is attestation, not PKI). After
// the handshake both derive an RFC 5705 exported-keying-material value, and the
// agent's attestation evidence commits to bindData = H(agentCertKey || exporter)
// and the run nonce. Including the exporter makes evidence non-relayable across
// sessions; including the cert key proves liveness of the TEE that finished the
// handshake. The provider-specific evidence production/verification is injected as
// an Issuer/Validator, so this package stays evidence-agnostic.
package atls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"time"
)

const (
	exporterLabel = "dispatcher/confidential/atls/v1"
	exporterLen   = 32
	nonceLen      = 32
	// maxEvidence bounds a single evidence message: a SEV-SNP report + cert table,
	// an MAA JWT, or a Nitro COSE document all fit comfortably under 1 MiB.
	maxEvidence = 1 << 20
)

// Issuer produces attestation evidence inside the TEE that commits to bindData
// (this package's session+key binding) and the per-run nonce. In production it is
// backed by the per-cloud agent producers; tests inject a synthetic issuer.
type Issuer interface {
	Issue(ctx context.Context, bindData, nonce []byte) ([]byte, error)
}

// Validator verifies attestation evidence: that it is a genuine measured TEE and
// commits to the expected bindData + nonce. Backed by the per-cloud verifiers.
type Validator interface {
	Validate(ctx context.Context, evidence, bindData, nonce []byte) error
}

// NewServerConfig returns a TLS 1.3 server config whose certificate is a fresh
// ephemeral P-256 key generated in-process (the private key never leaves the TEE),
// plus that key's PKIX SubjectPublicKeyInfo, which the attestation binds.
func NewServerConfig() (*tls.Config, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dispatcher-confidential-agent"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC), // validity is irrelevant: trust is attestation
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	return cfg, spki, nil
}

// NewClientConfig returns a TLS 1.3 client config that skips PKI verification —
// trust comes from the attestation exchange, not a CA. The server's presented key
// is captured post-handshake and folded into bindData.
func NewClientConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // trust is attestation, not PKI (see ClientAttest)
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
}

// bindData binds the completed handshake to the agent's key: SHA-256 over the
// server certificate's SPKI concatenated with the session's exported keying
// material.
func bindData(certSPKI, exporter []byte) []byte {
	h := sha256.New()
	h.Write(certSPKI)
	h.Write(exporter)
	return h.Sum(nil)
}

// ServerAttest runs the agent side of the exchange over conn: complete the
// handshake, read the client's nonce, produce evidence committing to
// bindData(cert, exporter) + nonce, and send it. certSPKI is from NewServerConfig.
func ServerAttest(ctx context.Context, conn *tls.Conn, certSPKI []byte, issuer Issuer) error {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
		defer conn.SetDeadline(time.Time{})
	}
	exporter, err := handshakeAndExport(ctx, conn)
	if err != nil {
		return err
	}
	nonce, err := readMsg(conn, nonceLen)
	if err != nil {
		return fmt.Errorf("atls read nonce: %w", err)
	}
	if len(nonce) != nonceLen {
		return fmt.Errorf("atls nonce is %d bytes, want %d", len(nonce), nonceLen)
	}
	evidence, err := issuer.Issue(ctx, bindData(certSPKI, exporter), nonce)
	if err != nil {
		return fmt.Errorf("atls issue: %w", err)
	}
	if err := writeMsg(conn, evidence); err != nil {
		return fmt.Errorf("atls send evidence: %w", err)
	}
	return nil
}

// ClientAttest runs the dispatcher side: complete the handshake, send a fresh
// nonce, read the agent's evidence, and validate it against
// bindData(serverKeyWeSaw, exporter) + nonce. Returns nil only if the evidence is
// a genuine measured TEE bound to THIS session.
func ClientAttest(ctx context.Context, conn *tls.Conn, validator Validator) error {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
		defer conn.SetDeadline(time.Time{})
	}
	exporter, err := handshakeAndExport(ctx, conn)
	if err != nil {
		return err
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("atls: peer presented no certificate")
	}
	peerSPKI, err := x509.MarshalPKIXPublicKey(state.PeerCertificates[0].PublicKey)
	if err != nil {
		return fmt.Errorf("atls peer key: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if err := writeMsg(conn, nonce); err != nil {
		return fmt.Errorf("atls send nonce: %w", err)
	}
	evidence, err := readMsg(conn, maxEvidence)
	if err != nil {
		return fmt.Errorf("atls read evidence: %w", err)
	}
	return validator.Validate(ctx, evidence, bindData(peerSPKI, exporter), nonce)
}

// handshakeAndExport completes the TLS handshake under ctx and returns the
// session's exported keying material. The caller sets the conn deadline so it
// spans the handshake and the post-handshake exchange.
func handshakeAndExport(ctx context.Context, conn *tls.Conn) ([]byte, error) {
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("atls handshake: %w", err)
	}
	state := conn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, exporterLen)
	if err != nil {
		return nil, fmt.Errorf("atls exporter: %w", err)
	}
	return exporter, nil
}

// writeMsg frames a message with a 4-byte big-endian length prefix.
func writeMsg(w io.Writer, b []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// readMsg reads one length-prefixed message, rejecting anything over max.
func readMsg(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int(n) > max {
		return nil, fmt.Errorf("message length %d exceeds max %d", n, max)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
