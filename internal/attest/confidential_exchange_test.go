package attest

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

// tokenMinter returns an agent.AttestFunc that mints a CS token binding [runNonce,
// SHA-256(channelPub)] in eat_nonce (standing in for the teeserver), signed by
// the given test key.
func tokenMinter(t *testing.T, signKey crypto.Signer) agent.AttestFunc {
	return func(_ context.Context, runNonce, channelPub []byte) (string, error) {
		sum := sha256.Sum256(channelPub)
		c := validCSClaims()
		c["eat_nonce"] = []string{hex.EncodeToString(runNonce), hex.EncodeToString(sum[:])}
		return mintJWT(t, "maa1", "RS256", signKey, c), nil
	}
}

// TestConfidentialAgent_AttestBindsChannelKey drives the agent's /attest over
// HTTP and confirms the returned token binds both the run nonce and the agent's
// channel key — the exact contract the dispatcher-side verifier enforces.
func TestConfidentialAgent_AttestBindsChannelKey(t *testing.T) {
	signKey, keys := jwtSigningKey(t)
	ag, err := agent.NewAgent(tokenMinter(t, signKey), nil)
	require.NoError(t, err)
	srv := httptest.NewServer(ag.Handler())
	t.Cleanup(srv.Close)

	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = 0x7E
	}
	ev, err := csEndpointFetch(srv.URL)(context.Background(), nonce)
	require.NoError(t, err)
	require.NotEmpty(t, ev.channelKey, "agent must return its channel public key")

	// The token must satisfy the full bound policy (nonce + channel key).
	_, _, err = verifyCSToken(ev.token, keys, CSPolicy{
		Nonce: nonce, ImageDigests: []string{csDigest}, ChannelKey: ev.channelKey,
	})
	require.NoError(t, err, "attest token must bind this run's nonce and the agent's channel key")
}

// TestConfidentialExchange_SealedRoundTrip runs the whole sealed R9 loop against
// a real agent (fake runner): attest+verify, seal the payload to the attested
// channel key, POST it, and pull back a result sealed to dispatcher's result key.
func TestConfidentialExchange_SealedRoundTrip(t *testing.T) {
	signKey, keys := jwtSigningKey(t)

	var gotPayload agent.Payload
	ag, err := agent.NewAgent(tokenMinter(t, signKey), func(_ context.Context, p agent.Payload) agent.Result {
		gotPayload = p
		return agent.Result{ExitCode: 0, Stdout: []byte("trained on " + string(p.DotEnv))}
	})
	require.NoError(t, err)
	srv := httptest.NewServer(ag.Handler())
	t.Cleanup(srv.Close)

	// 1. Attest + verify through the real attester (generates its own nonce).
	att := &csAttester{keys: keys, fetch: csEndpointFetch(srv.URL)}
	res, err := att.Verify(context.Background(),
		types.ConfidentialRequirement{Required: true, Type: "sev", Measurements: []string{csDigest}})
	require.NoError(t, err)
	require.True(t, res.Verified, res.Verdict)
	require.NotEmpty(t, res.ChannelKey, "a verified result must carry the bound channel key to seal to")

	// 2. Seal a payload to the attested key, run it, pull back the sealed result.
	payload := agent.Payload{Command: []string{"python", "train.py"}, DotEnv: []byte("SECRET=1")}
	result, err := agent.RunSealedExchange(context.Background(), srv.URL, res.ChannelKey, payload)
	require.NoError(t, err)

	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, "trained on SECRET=1", string(result.Stdout))
	assert.Equal(t, []string{"python", "train.py"}, gotPayload.Command, "the agent must have opened the sealed command")
	assert.NotEmpty(t, gotPayload.ResultPubKey, "dispatcher must have handed the agent a key to seal the result to")
}
