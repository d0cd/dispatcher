package attest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
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
		"not sev hardware":             {mutate: func(c map[string]any) { c["hwmodel"] = "GCP_INTEL_TDX" }, want: "SEV"},
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

// The Confidential Space token carries no reported TCB, so the CS path cannot
// enforce a minTCB floor. It must fail closed (loudly) when one is configured
// rather than silently ignore it — mirroring the Azure MAA path.
func TestCSAttester_MinTCBFailsClosed(t *testing.T) {
	channelKey := bytes.Repeat([]byte{0x22}, 32)
	sum := sha256.Sum256(channelKey)
	key, keys := jwtSigningKey(t)
	att := &csAttester{keys: keys,
		fetch: func(_ context.Context, nonce []byte) (csEvidence, error) {
			c := validCSClaims()
			c["eat_nonce"] = []string{hex.EncodeToString(nonce), hex.EncodeToString(sum[:])}
			return csEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: channelKey}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev", Measurements: []string{csDigest}, MinTCB: 7}

	_, err := att.Verify(context.Background(), req)
	require.Error(t, err, "minTCB set on the GCP CS path must fail closed, not be ignored")
	assert.Contains(t, err.Error(), "minTCB")
}

func TestCSAttester_BindsChannelKey(t *testing.T) {
	channelKey := bytes.Repeat([]byte{0x22}, 32)
	sum := sha256.Sum256(channelKey)
	key, keys := jwtSigningKey(t)
	att := &csAttester{keys: keys,
		fetch: func(_ context.Context, nonce []byte) (csEvidence, error) {
			c := validCSClaims()
			c["eat_nonce"] = []string{hex.EncodeToString(nonce), hex.EncodeToString(sum[:])}
			return csEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: channelKey}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev", Measurements: []string{csDigest}}

	res, err := att.Verify(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, res.Verified, "a token committing to the agent's channel key verifies")
}

func TestCSAttester_RejectsUncommittedChannelKey(t *testing.T) {
	key, keys := jwtSigningKey(t)
	att := &csAttester{keys: keys,
		fetch: func(_ context.Context, nonce []byte) (csEvidence, error) {
			c := validCSClaims()
			c["eat_nonce"] = []string{hex.EncodeToString(nonce)} // nonce echoed, key NOT committed
			return csEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: bytes.Repeat([]byte{0x33}, 32)}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev", Measurements: []string{csDigest}}

	res, err := att.Verify(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, res.Verified, "an unbound sealing key must be rejected — the host could have substituted it")
	assert.Contains(t, res.Verdict, "channel key")
}

func TestCSAttester_VerifyAccepts(t *testing.T) {
	channelKey := bytes.Repeat([]byte{0x44}, 32)
	sum := sha256.Sum256(channelKey)
	key, keys := jwtSigningKey(t)
	att := &csAttester{keys: keys,
		fetch: func(_ context.Context, nonce []byte) (csEvidence, error) {
			c := validCSClaims()
			c["eat_nonce"] = []string{hex.EncodeToString(nonce), hex.EncodeToString(sum[:])} // echo nonce + commit key
			return csEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: channelKey}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev", Measurements: []string{csDigest}}

	res, err := att.Verify(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, res.Verified)
	assert.Equal(t, csDigest, res.Measurement)
}

func TestCSAttester_RejectsReplay(t *testing.T) {
	key, keys := jwtSigningKey(t)
	att := &csAttester{keys: keys,
		fetch: func(_ context.Context, _ []byte) (csEvidence, error) {
			c := validCSClaims() // eat_nonce is a STALE nonce, not this run's
			return csEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: bytes.Repeat([]byte{0x44}, 32)}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev", Measurements: []string{csDigest}}

	res, err := att.Verify(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, res.Verified, "a token not echoing this run's nonce is rejected")
	assert.Contains(t, res.Verdict, "nonce")
}

func TestCSAttester_NotReadyAndNoFetch(t *testing.T) {
	_, err := (&csAttester{}).Verify(context.Background(),
		types.ConfidentialRequirement{Required: true, Type: "sev"})
	require.Error(t, err, "no fetch wired must error, not panic")
}

// GCP Confidential Space provisions plain SEV, so a sev-snp/tdx request must be
// rejected (not silently downgraded) and the recorded type must be the real one.
func TestCSAttester_RejectsTypeDowngrade(t *testing.T) {
	channelKey := bytes.Repeat([]byte{0x22}, 32)
	sum := sha256.Sum256(channelKey)
	key, keys := jwtSigningKey(t)
	att := &csAttester{keys: keys,
		fetch: func(_ context.Context, nonce []byte) (csEvidence, error) {
			c := validCSClaims() // hwmodel GCP_AMD_SEV
			c["eat_nonce"] = []string{hex.EncodeToString(nonce), hex.EncodeToString(sum[:])}
			return csEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: channelKey}, nil
		}}

	res, err := att.Verify(context.Background(), types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{csDigest}})
	require.NoError(t, err)
	assert.False(t, res.Verified, "a sev-snp request on a SEV platform must be rejected, not downgraded")
	assert.Contains(t, res.Verdict, "type")

	res, err = att.Verify(context.Background(), types.ConfidentialRequirement{Required: true, Type: "sev", Measurements: []string{csDigest}})
	require.NoError(t, err)
	assert.True(t, res.Verified)
	assert.Equal(t, "sev", res.Type, "the recorded TEE type must be the real attested platform (SEV), not a hardcoded sev-snp")
}

// The run path always seals to a channel key, so an absent key must fail closed
// at the verifier (not skip the binding check) — matching the matrix's "Enforced".
func TestCSAttester_RejectsAbsentChannelKey(t *testing.T) {
	key, keys := jwtSigningKey(t)
	att := &csAttester{keys: keys,
		fetch: func(_ context.Context, nonce []byte) (csEvidence, error) {
			c := validCSClaims()
			c["eat_nonce"] = []string{hex.EncodeToString(nonce)}
			return csEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: nil}, nil // no channel key
		}}
	res, err := att.Verify(context.Background(), types.ConfidentialRequirement{Required: true, Type: "sev", Measurements: []string{csDigest}})
	require.NoError(t, err)
	assert.False(t, res.Verified, "an absent channel key must be rejected, not silently skip the binding")
	assert.Contains(t, res.Verdict, "channel key")
}
