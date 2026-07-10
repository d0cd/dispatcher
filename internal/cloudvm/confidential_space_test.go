package cloudvm

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var csNonce = bytes.Repeat([]byte{0xAB}, 32)

const csDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func validCSClaims() map[string]any {
	return map[string]any{
		"iss":       csIssuer,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"eat_nonce": []string{hex.EncodeToString(csNonce)},
		"hwmodel":   "GCP_AMD_SEV",
		"swname":    "CONFIDENTIAL_SPACE",
		"dbgstat":   "disabled-since-boot",
		"submods": map[string]any{
			"container": map[string]any{"image_digest": csDigest},
		},
	}
}

func csPolicy() CSPolicy {
	return CSPolicy{Nonce: csNonce, ImageDigests: []string{csDigest}}
}

func TestVerifyCSToken_Accepts(t *testing.T) {
	key, keys := maaSigningKey(t)
	tok := mintJWT(t, "maa1", "RS256", key, validCSClaims())

	digest, err := verifyCSToken(tok, keys, csPolicy())
	require.NoError(t, err)
	assert.Equal(t, csDigest, digest, "returns the attested container image digest")
}

// eat_nonce may be a bare string, not just an array.
func TestVerifyCSToken_AcceptsStringNonce(t *testing.T) {
	key, keys := maaSigningKey(t)
	c := validCSClaims()
	c["eat_nonce"] = hex.EncodeToString(csNonce) // single string form
	_, err := verifyCSToken(mintJWT(t, "maa1", "RS256", key, c), keys, csPolicy())
	require.NoError(t, err)
}

func TestVerifyCSToken_RejectsBadSignature(t *testing.T) {
	key, _ := maaSigningKey(t)
	_, otherKeys := maaSigningKey(t)
	tok := mintJWT(t, "maa1", "RS256", key, validCSClaims())
	_, err := verifyCSToken(tok, otherKeys, csPolicy())
	require.Error(t, err, "a token not signed by a trusted Google key must be rejected")
}

func TestVerifyCSToken_Rejects(t *testing.T) {
	cases := map[string]struct {
		mutate func(c map[string]any)
		policy func(p *CSPolicy)
		want   string
	}{
		"wrong issuer":                 {mutate: func(c map[string]any) { c["iss"] = "https://evil.example" }, want: "issuer"},
		"expired":                      {mutate: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, want: "expired"},
		"nonce not echoed":             {mutate: func(c map[string]any) { c["eat_nonce"] = []string{"deadbeef"} }, want: "nonce"},
		"not confidential-space":       {mutate: func(c map[string]any) { c["swname"] = "SOMETHING_ELSE" }, want: "CONFIDENTIAL_SPACE"},
		"not sev hardware":             {mutate: func(c map[string]any) { c["hwmodel"] = "GCP_INTEL_TDX" }, want: "SEV"},
		"debug enabled":                {mutate: func(c map[string]any) { c["dbgstat"] = "enabled-since-boot" }, want: "debug"},
		"digest not allowed":           {policy: func(p *CSPolicy) { p.ImageDigests = []string{"sha256:other"} }, want: "allowlist"},
		"empty allowlist fails closed": {policy: func(p *CSPolicy) { p.ImageDigests = nil }, want: "allowlist"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			key, keys := maaSigningKey(t)
			c := validCSClaims()
			if tc.mutate != nil {
				tc.mutate(c)
			}
			p := csPolicy()
			if tc.policy != nil {
				tc.policy(&p)
			}
			_, err := verifyCSToken(mintJWT(t, "maa1", "RS256", key, c), keys, p)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
