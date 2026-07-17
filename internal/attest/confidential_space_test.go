package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
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
		"aud":       CSTokenAudience,
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
	key, keys := jwtSigningKey(t)
	tok := mintJWT(t, "maa1", "RS256", key, validCSClaims())

	digest, _, err := verifyCSToken(tok, keys, csPolicy())
	require.NoError(t, err)
	assert.Equal(t, csDigest, digest, "returns the attested container image digest")
}

// eat_nonce may be a bare string, not just an array.
func TestVerifyCSToken_AcceptsStringNonce(t *testing.T) {
	key, keys := jwtSigningKey(t)
	c := validCSClaims()
	c["eat_nonce"] = hex.EncodeToString(csNonce) // single string form
	_, _, err := verifyCSToken(mintJWT(t, "maa1", "RS256", key, c), keys, csPolicy())
	require.NoError(t, err)
}

// A TDX Confidential Space token is a legitimate confidential platform and must
// verify (the type gate only rejects a mismatch against an explicit request).
func TestVerifyCSToken_AcceptsTDX(t *testing.T) {
	key, keys := jwtSigningKey(t)
	c := validCSClaims()
	c["hwmodel"] = "GCP_INTEL_TDX"
	_, teeType, err := verifyCSToken(mintJWT(t, "maa1", "RS256", key, c), keys, csPolicy())
	require.NoError(t, err)
	assert.Equal(t, "tdx", teeType)
}

// A token minted for a different audience must be rejected when the policy pins
// an expected audience.
func TestVerifyCSToken_RejectsWrongAudience(t *testing.T) {
	key, keys := jwtSigningKey(t)
	c := validCSClaims()
	c["aud"] = "some-other-relying-party"
	p := csPolicy()
	p.ExpectedAudience = CSTokenAudience
	_, _, err := verifyCSToken(mintJWT(t, "maa1", "RS256", key, c), keys, p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}

func TestVerifyCSToken_RejectsBadSignature(t *testing.T) {
	key, _ := jwtSigningKey(t)
	_, otherKeys := jwtSigningKey(t)
	tok := mintJWT(t, "maa1", "RS256", key, validCSClaims())
	_, _, err := verifyCSToken(tok, otherKeys, csPolicy())
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
		"missing exp":                  {mutate: func(c map[string]any) { delete(c, "exp") }, want: "exp"},
		"not yet valid (nbf)":          {mutate: func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, want: "not yet valid"},
		"nonce not echoed":             {mutate: func(c map[string]any) { c["eat_nonce"] = []string{"deadbeef"} }, want: "nonce"},
		"not confidential-space":       {mutate: func(c map[string]any) { c["swname"] = "SOMETHING_ELSE" }, want: "CONFIDENTIAL_SPACE"},
		"unknown hardware platform":    {mutate: func(c map[string]any) { c["hwmodel"] = "GCP_MYSTERY_BOX" }, want: "recognized confidential platform"},
		"debug enabled":                {mutate: func(c map[string]any) { c["dbgstat"] = "enabled-since-boot" }, want: "debug"},
		"digest not allowed":           {policy: func(p *CSPolicy) { p.ImageDigests = []string{"sha256:other"} }, want: "allowlist"},
		"empty allowlist fails closed": {policy: func(p *CSPolicy) { p.ImageDigests = nil }, want: "allowlist"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			key, keys := jwtSigningKey(t)
			c := validCSClaims()
			if tc.mutate != nil {
				tc.mutate(c)
			}
			p := csPolicy()
			if tc.policy != nil {
				tc.policy(&p)
			}
			_, _, err := verifyCSToken(mintJWT(t, "maa1", "RS256", key, c), keys, p)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestVerifyCSToken_ChannelKeyBinding(t *testing.T) {
	channelKey := bytes.Repeat([]byte{0x11}, 32)
	sum := sha256.Sum256(channelKey)
	keyNonce := hex.EncodeToString(sum[:])

	t.Run("accepts when eat_nonce commits to the channel key", func(t *testing.T) {
		key, keys := jwtSigningKey(t)
		c := validCSClaims()
		c["eat_nonce"] = []string{hex.EncodeToString(csNonce), keyNonce}
		p := csPolicy()
		p.ChannelKey = channelKey
		_, _, err := verifyCSToken(mintJWT(t, "maa1", "RS256", key, c), keys, p)
		require.NoError(t, err)
	})

	t.Run("rejects when the channel key is not committed (relay/substitution)", func(t *testing.T) {
		key, keys := jwtSigningKey(t)
		c := validCSClaims() // only the run nonce, no channel-key commitment
		p := csPolicy()
		p.ChannelKey = channelKey
		_, _, err := verifyCSToken(mintJWT(t, "maa1", "RS256", key, c), keys, p)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "channel key")
	})

	t.Run("nil channel key skips the binding (verify-only path)", func(t *testing.T) {
		key, keys := jwtSigningKey(t)
		_, _, err := verifyCSToken(mintJWT(t, "maa1", "RS256", key, validCSClaims()), keys, csPolicy())
		require.NoError(t, err, "the golden verify-only path must keep working")
	})
}

// csTokenBoundTo mints a CS token whose eat_nonce echoes the run nonce and commits
// to the aTLS session bindData (SHA-256(bindData)) — what the honest agent emits.
func csTokenBoundTo(t *testing.T, key crypto.Signer, bindData []byte, mutate func(map[string]any)) string {
	t.Helper()
	sum := sha256.Sum256(bindData)
	c := validCSClaims()
	c["eat_nonce"] = []string{hex.EncodeToString(csNonce), hex.EncodeToString(sum[:])}
	if mutate != nil {
		mutate(c)
	}
	return mintJWT(t, "maa1", "RS256", key, c)
}

// The Confidential Space token carries no reported TCB, so the aTLS CS validator
// cannot enforce a minTCB floor. It must fail closed (loudly) when one is
// configured rather than silently ignore it — mirroring the Azure SNP path.
func TestCSValidator_MinTCBFailsClosed(t *testing.T) {
	key, keys := jwtSigningKey(t)
	bindData := bytes.Repeat([]byte{0x22}, 32)
	tok := csTokenBoundTo(t, key, bindData, nil)

	err := CSValidator(keys, []string{csDigest}, "sev", 7).Validate(context.Background(), []byte(tok), bindData, csNonce)
	require.Error(t, err, "minTCB set on the GCP CS path must fail closed, not be ignored")
	assert.Contains(t, err.Error(), "minTCB")
}

// A token committing to the aTLS session bindData verifies, and the recorded
// verdict carries the attested image digest + the real platform type.
func TestCSValidator_AcceptsBoundToken(t *testing.T) {
	key, keys := jwtSigningKey(t)
	bindData := bytes.Repeat([]byte{0x44}, 32)
	tok := csTokenBoundTo(t, key, bindData, nil)

	v := CSValidator(keys, []string{csDigest}, "sev", 0)
	require.NoError(t, v.Validate(context.Background(), []byte(tok), bindData, csNonce))
	assert.True(t, v.Result.Verified)
	assert.Equal(t, csDigest, v.Result.Measurement)
	assert.Equal(t, "sev", v.Result.Type)
}

// A token that does not commit to this session's bindData is a relay/substitution
// and must be rejected.
func TestCSValidator_RejectsUncommittedBindData(t *testing.T) {
	key, keys := jwtSigningKey(t)
	// Token commits to a DIFFERENT bindData than the session presents.
	tok := csTokenBoundTo(t, key, bytes.Repeat([]byte{0x33}, 32), nil)

	err := CSValidator(keys, []string{csDigest}, "sev", 0).Validate(context.Background(), []byte(tok), bytes.Repeat([]byte{0x22}, 32), csNonce)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel key")
}

// A token not echoing this run's nonce (a replay) is rejected.
func TestCSValidator_RejectsReplay(t *testing.T) {
	key, keys := jwtSigningKey(t)
	bindData := bytes.Repeat([]byte{0x44}, 32)
	sum := sha256.Sum256(bindData)
	c := validCSClaims()
	c["eat_nonce"] = []string{"deadbeef", hex.EncodeToString(sum[:])} // stale run nonce
	tok := mintJWT(t, "maa1", "RS256", key, c)

	err := CSValidator(keys, []string{csDigest}, "sev", 0).Validate(context.Background(), []byte(tok), bindData, csNonce)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce")
}

// GCP Confidential Space provisions plain SEV, so a sev-snp/tdx request must be
// rejected (not silently downgraded).
func TestCSValidator_RejectsTypeDowngrade(t *testing.T) {
	key, keys := jwtSigningKey(t)
	bindData := bytes.Repeat([]byte{0x22}, 32)
	tok := csTokenBoundTo(t, key, bindData, nil) // hwmodel GCP_AMD_SEV → "sev"

	err := CSValidator(keys, []string{csDigest}, "sev-snp", 0).Validate(context.Background(), []byte(tok), bindData, csNonce)
	require.Error(t, err, "a sev-snp request on a SEV platform must be rejected, not downgraded")
	assert.Contains(t, err.Error(), "type")
}
