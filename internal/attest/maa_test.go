package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

func maaSigningKey(t *testing.T) (*rsa.PrivateKey, map[string]crypto.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key, map[string]crypto.PublicKey{"maa1": &key.PublicKey}
}

const (
	maaIssuer      = "https://sharedeus.eus.attest.azure.net"
	maaMeasurement = "5b0ce64ad1c1f6375dbda5f760b98526"
)

var maaNonce = bytes.Repeat([]byte{0xC3}, 32)

// validMAAClaims builds a token in the real MAA CVM shape: SEV-SNP facts nested
// under x-ms-isolation-tee, the binding nonce echoed in the top-level
// x-ms-runtime.client-payload (base64).
func validMAAClaims() map[string]any {
	return map[string]any{
		"iss":                   maaIssuer,
		"exp":                   time.Now().Add(time.Hour).Unix(),
		"nbf":                   time.Now().Add(-time.Minute).Unix(),
		"x-ms-attestation-type": "azurevm",
		"x-ms-runtime": map[string]any{
			"client-payload": map[string]any{
				"nonce": base64.StdEncoding.EncodeToString(maaNonce),
			},
		},
		"x-ms-isolation-tee": map[string]any{
			"x-ms-attestation-type":           "sevsnpvm",
			"x-ms-compliance-status":          "azure-compliant-cvm",
			"x-ms-sevsnpvm-is-debuggable":     false,
			"x-ms-sevsnpvm-launchmeasurement": maaMeasurement,
		},
	}
}

func maaPolicy() MAAPolicy {
	return MAAPolicy{Issuer: maaIssuer, Nonce: maaNonce, Measurements: []string{maaMeasurement}}
}

func TestVerifyMAAToken_Accepts(t *testing.T) {
	key, keys := maaSigningKey(t)
	m, err := verifyMAAToken(mintJWT(t, "maa1", "RS256", key, validMAAClaims()), keys, maaPolicy())
	require.NoError(t, err)
	assert.Equal(t, maaMeasurement, m, "returns the attested launch measurement")
}

func TestVerifyMAAToken_RejectsBadSignature(t *testing.T) {
	key, _ := maaSigningKey(t)
	_, otherKeys := maaSigningKey(t)
	_, err := verifyMAAToken(mintJWT(t, "maa1", "RS256", key, validMAAClaims()), otherKeys, maaPolicy())
	require.Error(t, err, "a token not signed by a pinned MAA key must be rejected")
}

func TestVerifyMAAToken_Rejects(t *testing.T) {
	setTEE := func(c map[string]any, k string, v any) {
		c["x-ms-isolation-tee"].(map[string]any)[k] = v
	}
	cases := map[string]struct {
		mutate func(c map[string]any)
		policy func(p *MAAPolicy)
		want   string
	}{
		"wrong issuer":        {mutate: func(c map[string]any) { c["iss"] = "https://evil.attest.azure.net" }, want: "issuer"},
		"expired":             {mutate: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, want: "expired"},
		"missing exp":         {mutate: func(c map[string]any) { delete(c, "exp") }, want: "exp"},
		"not yet valid (nbf)": {mutate: func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, want: "not yet valid"},
		"nonce not bound": {mutate: func(c map[string]any) {
			c["x-ms-runtime"].(map[string]any)["client-payload"].(map[string]any)["nonce"] = base64.StdEncoding.EncodeToString([]byte("wrong"))
		}, want: "nonce"},
		"not sevsnpvm":            {mutate: func(c map[string]any) { setTEE(c, "x-ms-attestation-type", "tdxvm") }, want: "sevsnpvm"},
		"not compliant":           {mutate: func(c map[string]any) { setTEE(c, "x-ms-compliance-status", "non-compliant") }, want: "compliant"},
		"debuggable":              {mutate: func(c map[string]any) { setTEE(c, "x-ms-sevsnpvm-is-debuggable", true) }, want: "debug"},
		"measurement not allowed": {policy: func(p *MAAPolicy) { p.Measurements = []string{"other"} }, want: "allowlist"},
		"empty allowlist":         {policy: func(p *MAAPolicy) { p.Measurements = nil }, want: "allowlist"},
		"no issuer pinned":        {policy: func(p *MAAPolicy) { p.Issuer = "" }, want: "issuer must be set"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			key, keys := maaSigningKey(t)
			c := validMAAClaims()
			if tc.mutate != nil {
				tc.mutate(c)
			}
			p := maaPolicy()
			if tc.policy != nil {
				tc.policy(&p)
			}
			_, err := verifyMAAToken(mintJWT(t, "maa1", "RS256", key, c), keys, p)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestMAABindingNonce_BindsBothInputs(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x01}, 32)
	key := bytes.Repeat([]byte{0x02}, 32)
	base := agent.MAABindingNonce(nonce, key)
	assert.Len(t, base, 32, "SHA-256 output fits the TPM quote qualifying data")
	assert.NotEqual(t, base, agent.MAABindingNonce(bytes.Repeat([]byte{0x03}, 32), key), "a different nonce changes the binding")
	assert.NotEqual(t, base, agent.MAABindingNonce(nonce, bytes.Repeat([]byte{0x04}, 32)), "a different channel key changes the binding")
	// Concatenation is order-sensitive (no ambiguity between nonce and key).
	sum := sha256.Sum256(append(append([]byte{}, nonce...), key...))
	assert.Equal(t, sum[:], base)
}

func TestAzureAttester_BindsNonceAndChannelKey(t *testing.T) {
	key, keys := maaSigningKey(t)
	channelKey := bytes.Repeat([]byte{0x9A}, 32)
	att := &azureAttester{keys: keys, issuer: maaIssuer, isReady: true,
		fetch: func(_ context.Context, nonce []byte) (maaEvidence, error) {
			c := validMAAClaims()
			// echo the binding the guest would have supplied
			c["x-ms-runtime"].(map[string]any)["client-payload"].(map[string]any)["nonce"] =
				base64.StdEncoding.EncodeToString(agent.MAABindingNonce(nonce, channelKey))
			return maaEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: channelKey}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{maaMeasurement}}

	res, err := att.Verify(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, res.Verified)
	assert.Equal(t, maaMeasurement, res.Measurement)
	assert.Equal(t, channelKey, res.ChannelKey, "the verified channel key is carried for sealing")
}

func TestAzureAttester_RejectsUnboundToken(t *testing.T) {
	key, keys := maaSigningKey(t)
	att := &azureAttester{keys: keys, issuer: maaIssuer, isReady: true,
		fetch: func(_ context.Context, _ []byte) (maaEvidence, error) {
			c := validMAAClaims() // client-payload nonce is a stale constant, not this run's binding
			return maaEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: bytes.Repeat([]byte{0x9A}, 32)}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{maaMeasurement}}

	res, err := att.Verify(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, res.Verified, "a token not binding this run's nonce+key is rejected")
	assert.Contains(t, res.Verdict, "nonce")
}

func TestAzureAttester_NotReadyAndNoFetch(t *testing.T) {
	assert.False(t, (&azureAttester{}).ready())
	_, err := (&azureAttester{isReady: true}).Verify(context.Background(),
		types.ConfidentialRequirement{Required: true, Type: "sev-snp"})
	require.Error(t, err, "no fetch wired must error, not panic")
}

func TestAzureAttester_PropagatesFetchFailure(t *testing.T) {
	_, keys := maaSigningKey(t)
	att := &azureAttester{keys: keys, issuer: maaIssuer, isReady: true,
		fetch: func(_ context.Context, _ []byte) (maaEvidence, error) {
			return maaEvidence{}, assertErr("vTPM unavailable")
		}}
	_, err := att.Verify(context.Background(),
		types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{maaMeasurement}})
	require.Error(t, err, "a fetch failure is an error, not an unverified verdict")
}
