package cloudvm

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

	keys, err := parseRSAJWKS([]byte(jwks))
	require.NoError(t, err)
	got, ok := keys["k1"].(*rsa.PublicKey)
	require.True(t, ok, "kid must map to an RSA public key")
	assert.Equal(t, key.N, got.N)
	assert.Equal(t, key.E, got.E)
}

func TestParseRSAJWKS_Empty(t *testing.T) {
	_, err := parseRSAJWKS([]byte(`{"keys":[]}`))
	require.Error(t, err, "no keys is a fail-closed error, not an empty trust set")
}
