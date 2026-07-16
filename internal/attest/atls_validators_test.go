package attest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/attest/atls"
)

// atlsLoopback returns an un-handshaken atls client/server pair over real
// localhost TCP, plus the server cert's SPKI.
func atlsLoopback(t *testing.T) (client, server *tls.Conn, serverSPKI []byte) {
	t.Helper()
	cfg, spki, err := atls.NewServerConfig()
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	sc := make(chan *tls.Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			sc <- nil
			return
		}
		sc <- tls.Server(raw, cfg)
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() })
	s := <-sc
	require.NotNil(t, s)
	t.Cleanup(func() { s.Close() })
	return tls.Client(raw, atls.NewClientConfig()), s, spki
}

// TestATLS_CSVerifierEndToEnd runs the real Confidential Space verifier through
// the atls primitive over a live loopback TLS session: the token is minted binding
// bindData, and CSValidator verifies it commits to THIS session's bindData+nonce.
func TestATLS_CSVerifierEndToEnd(t *testing.T) {
	key, keys := jwtSigningKey(t)
	issuer := agent.IssuerFromAttest(func(_ context.Context, nonce, bindData []byte) (string, error) {
		c := validCSClaims()
		sum := sha256.Sum256(bindData)
		c["eat_nonce"] = []string{hex.EncodeToString(nonce), hex.EncodeToString(sum[:])}
		return mintJWT(t, "maa1", "RS256", key, c), nil
	})

	client, server, spki := atlsLoopback(t)
	ctx := context.Background()
	go func() { _ = atls.ServerAttest(ctx, server, spki, issuer) }()

	require.NoError(t, atls.ClientAttest(ctx, client, CSValidator(keys, []string{csDigest}, "")),
		"honest CS agent over aTLS must verify")
}

// TestATLS_CSVerifierRejectsWrongMeasurement proves the measurement allowlist is
// still enforced through the aTLS path.
func TestATLS_CSVerifierRejectsWrongMeasurement(t *testing.T) {
	key, keys := jwtSigningKey(t)
	issuer := agent.IssuerFromAttest(func(_ context.Context, nonce, bindData []byte) (string, error) {
		c := validCSClaims()
		sum := sha256.Sum256(bindData)
		c["eat_nonce"] = []string{hex.EncodeToString(nonce), hex.EncodeToString(sum[:])}
		return mintJWT(t, "maa1", "RS256", key, c), nil
	})

	client, server, spki := atlsLoopback(t)
	ctx := context.Background()
	go func() { _ = atls.ServerAttest(ctx, server, spki, issuer) }()

	wrongDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	require.Error(t, atls.ClientAttest(ctx, client, CSValidator(keys, []string{wrongDigest}, "")),
		"a token whose image digest isn't allowlisted must be rejected through aTLS")
}
