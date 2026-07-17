package attest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRSAJWKS_RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	jwks := fmt.Sprintf(`{"keys":[{"kid":"k1","kty":"RSA","n":%q,"e":%q}]}`, n, e)

	keys, err := parseJWKS([]byte(jwks))
	require.NoError(t, err)
	got, ok := keys["k1"].(*rsa.PublicKey)
	require.True(t, ok, "kid must map to an RSA public key")
	assert.Equal(t, key.N, got.N)
	assert.Equal(t, key.E, got.E)
}

func TestParseRSAJWKS_Empty(t *testing.T) {
	_, err := parseJWKS([]byte(`{"keys":[]}`))
	require.Error(t, err, "no keys is a fail-closed error, not an empty trust set")
}

func TestParseRSAJWKS_RejectsEmptyKid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	jwks := fmt.Sprintf(`{"keys":[{"kid":"","kty":"RSA","n":%q,"e":%q}]}`, n, e)
	_, err = parseJWKS([]byte(jwks))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty kid")
}

func TestRSAPublicKeyFromJWK_RejectsBadParams(t *testing.T) {
	valid, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	// An oversized exponent (>4 bytes) that Int64 would truncate is rejected.
	_, err = rsaPublicKeyFromJWK(valid.N.Bytes(), []byte{1, 0, 0, 0, 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exponent")
	// An even exponent is rejected.
	_, err = rsaPublicKeyFromJWK(valid.N.Bytes(), []byte{0x02})
	require.Error(t, err)
	// A too-small modulus is rejected.
	_, err = rsaPublicKeyFromJWK(big.NewInt(3).Bytes(), []byte{0x01, 0x00, 0x01})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "modulus")
	// The genuine key parses.
	_, err = rsaPublicKeyFromJWK(valid.N.Bytes(), []byte{0x01, 0x00, 0x01})
	require.NoError(t, err)
}

func TestRequireGoogleHTTPSURL(t *testing.T) {
	for _, ok := range []string{"https://www.googleapis.com/oauth2/v3/certs", "https://googleapis.com/x"} {
		assert.NoError(t, requireGoogleHTTPSURL(ok), ok)
	}
	for _, bad := range []string{"http://www.googleapis.com/x", "https://evil.example/x", "https://googleapis.com.evil.com/x"} {
		assert.Error(t, requireGoogleHTTPSURL(bad), bad)
	}
}
