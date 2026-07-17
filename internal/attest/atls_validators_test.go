package attest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

	require.NoError(t, atls.ClientAttest(ctx, client, CSValidator(keys, []string{csDigest}, "", 0)),
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
	require.Error(t, atls.ClientAttest(ctx, client, CSValidator(keys, []string{wrongDigest}, "", 0)),
		"a token whose image digest isn't allowlisted must be rejected through aTLS")
}

// TestATLS_NitroVerifierEndToEnd runs the real Nitro COSE verifier through the
// atls primitive over live loopback TLS: the enclave's document binds bindData in
// its public_key field, and NitroValidator checks it matches THIS session.
func TestATLS_NitroVerifierEndToEnd(t *testing.T) {
	root, rootKey := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	issuer := agent.IssuerFromAttest(func(_ context.Context, nonce, bindData []byte) (string, error) {
		cose := signedNitroDoc(t, root, rootKey, func(d *nitroDoc) {
			d.Nonce = nonce
			d.PublicKey = bindData
		})
		return base64.StdEncoding.EncodeToString(cose), nil
	})

	client, server, spki := atlsLoopback(t)
	ctx := context.Background()
	go func() { _ = atls.ServerAttest(ctx, server, spki, issuer) }()

	validator := NitroValidator(pool, map[int]string{0: hex.EncodeToString(nitroPCR(0x0A))})
	require.NoError(t, atls.ClientAttest(ctx, client, validator), "honest Nitro agent over aTLS must verify")
}

// TestAzureSNPValidator exercises the azure-snp Validator adapter directly (the
// TLS transport is proven by the CS/primitive tests): a real SNP+vTPM bundle bound
// to bindData verifies, and one bound to a different session is rejected.
func TestAzureSNPValidator(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x5a}, 32)
	bindData := bytes.Repeat([]byte{0x9a}, 32)
	pcr11 := make48(0xAB)[:32]

	ev, roots := azureEvidence(t, nonce, bindData, pcr11, nil)
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	evidence := []byte(base64.StdEncoding.EncodeToString(raw))

	val := AzureSNPValidator(roots, map[int]string{11: hex.EncodeToString(pcr11)}, 0)
	ctx := context.Background()
	require.NoError(t, val.Validate(ctx, evidence, bindData, nonce),
		"a bundle bound to this session's bindData must verify")

	other := bytes.Repeat([]byte{0x11}, 32)
	require.Error(t, val.Validate(ctx, evidence, other, nonce),
		"a bundle bound to a different session must be rejected")
}
