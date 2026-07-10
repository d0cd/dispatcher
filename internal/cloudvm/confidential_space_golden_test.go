package cloudvm

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwkRSAKeys parses a standard JWK Set of RSA keys (n/e) — the format Google's
// Confidential Space JWKS uses — into a kid->key map.
func jwkRSAKeys(t *testing.T, raw []byte) map[string]crypto.PublicKey {
	t.Helper()
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	keys := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		require.NoError(t, err)
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		require.NoError(t, err)
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(new(big.Int).SetBytes(eb).Int64()),
		}
	}
	return keys
}

// TestGolden_CSToken verifies dispatcher's Confidential Space verifier against a
// REAL Google-signed attestation token captured from a live CS VM. Fixtures are
// git-ignored, so the test skips without them; the token expires ~1h after
// capture, so re-running needs a fresh capture (see experiments/.../capture).
func TestGolden_CSToken(t *testing.T) {
	dir := filepath.Join(fixturesDir(), "cs")
	token := strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "token.jwt"))))
	jwks := skipUnlessFixture(t, filepath.Join(dir, "jwks.json"))
	nonceHex := strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "nonce.hex"))))
	wantDigest := strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "digest.txt"))))

	nonce, err := hex.DecodeString(nonceHex)
	require.NoError(t, err)

	digest, err := verifyCSToken(token, jwkRSAKeys(t, jwks), CSPolicy{
		Nonce: nonce, ImageDigests: []string{wantDigest},
	})
	require.NoError(t, err, "a real Google-signed CS token must verify (confirms signature + claim names + eat_nonce binding + image digest)")
	assert.Equal(t, wantDigest, digest)
}
