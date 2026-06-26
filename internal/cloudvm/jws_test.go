package cloudvm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// mintJWT builds a signed compact JWS for tests.
func mintJWT(t *testing.T, kid, alg string, key crypto.Signer, payload map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid})
	pl, _ := json.Marshal(payload)
	signingInput := b64url(hdr) + "." + b64url(pl)
	digest := sha256.Sum256([]byte(signingInput))

	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		require.NoError(t, err)
		sig = s
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		require.NoError(t, err)
		sig = append(leftPad(r.Bytes(), 32), leftPad(s.Bytes(), 32)...)
	default:
		t.Fatalf("unsupported test key")
	}
	return signingInput + "." + b64url(sig)
}

func TestVerifyJWS_RS256(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]crypto.PublicKey{"k1": &key.PublicKey}
	tok := mintJWT(t, "k1", "RS256", key, map[string]any{"foo": "bar"})

	payload, err := verifyJWS(tok, keys)
	require.NoError(t, err)
	assert.Contains(t, string(payload), "bar")
}

func TestVerifyJWS_ES256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := map[string]crypto.PublicKey{"k1": &key.PublicKey}
	tok := mintJWT(t, "k1", "ES256", key, map[string]any{"foo": "bar"})

	payload, err := verifyJWS(tok, keys)
	require.NoError(t, err)
	assert.Contains(t, string(payload), "bar")
}

func TestVerifyJWS_RejectsTamperedPayload(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]crypto.PublicKey{"k1": &key.PublicKey}
	tok := mintJWT(t, "k1", "RS256", key, map[string]any{"foo": "bar"})

	_, err := verifyJWS(tok[:len(tok)-8]+"AAAAAAAA", keys)
	assert.Error(t, err, "a tampered signature must be rejected")
}

func TestVerifyJWS_RejectsUnsafeAlgs(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]crypto.PublicKey{"k1": &key.PublicKey}
	for _, alg := range []string{"none", "HS256"} {
		hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": "k1"})
		pl, _ := json.Marshal(map[string]any{"foo": "bar"})
		tok := b64url(hdr) + "." + b64url(pl) + ".AAAA"
		_, err := verifyJWS(tok, keys)
		assert.Error(t, err, "alg %q must be rejected (algorithm confusion)", alg)
	}
}

func TestVerifyJWS_RejectsMalformed(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]crypto.PublicKey{"k1": &key.PublicKey}
	good := mintJWT(t, "k1", "RS256", key, map[string]any{"foo": "bar"})

	cases := map[string]string{
		"too few parts":        "aaa.bbb",
		"bad base64 header":    "!!!." + strings.SplitN(good, ".", 2)[1],
		"bad base64 signature": strings.Join(strings.Split(good, ".")[:2], ".") + ".!!!",
		"non-json header":      b64url([]byte("not-json")) + ".x.y",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := verifyJWS(tok, keys)
			assert.Error(t, err, "malformed token must error, not panic")
		})
	}
}

func TestVerifyJWS_UnknownKid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := mintJWT(t, "k1", "RS256", key, map[string]any{"foo": "bar"})
	_, err := verifyJWS(tok, map[string]crypto.PublicKey{"other": &key.PublicKey})
	assert.Error(t, err)
}

func TestVerifyJWS_WrongKeyType(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// RS256 header but an EC key registered → must reject, not panic.
	tok := mintJWT(t, "k1", "RS256", rsaKey, map[string]any{"foo": "bar"})
	_, err := verifyJWS(tok, map[string]crypto.PublicKey{"k1": &ec.PublicKey})
	assert.Error(t, err)
}
