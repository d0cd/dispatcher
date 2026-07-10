package cloudvm

import (
	"context"
	"crypto"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

// tokenMinter returns a fetchToken that mints a CS token echoing the requested
// nonces (standing in for the teeserver), signed by the given test key.
func tokenMinter(t *testing.T, signKey crypto.Signer) func(context.Context, []string) (string, error) {
	return func(_ context.Context, nonces []string) (string, error) {
		c := validCSClaims()
		c["eat_nonce"] = nonces
		return mintJWT(t, "maa1", "RS256", signKey, c), nil
	}
}

// TestConfidentialAgent_AttestBindsChannelKey drives the agent's /attest over
// HTTP and confirms the returned token binds both the run nonce and the agent's
// channel key — the exact contract the dispatcher-side verifier enforces.
func TestConfidentialAgent_AttestBindsChannelKey(t *testing.T) {
	signKey, keys := maaSigningKey(t)
	agent, err := newConfidentialAgent(agentConfig{fetchToken: tokenMinter(t, signKey)})
	require.NoError(t, err)
	srv := httptest.NewServer(agent.handler())
	t.Cleanup(srv.Close)

	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = 0x7E
	}
	ev, err := csEndpointFetch(srv.URL)(context.Background(), &VMInfo{}, "", "", nonce)
	require.NoError(t, err)
	require.NotEmpty(t, ev.channelKey, "agent must return its channel public key")

	// The token must satisfy the full bound policy (nonce + channel key).
	_, err = verifyCSToken(ev.token, keys, CSPolicy{
		Nonce: nonce, ImageDigests: []string{csDigest}, ChannelKey: ev.channelKey,
	})
	require.NoError(t, err, "attest token must bind this run's nonce and the agent's channel key")
}

// TestConfidentialExchange_SealedRoundTrip runs the whole sealed R9 loop against
// a real agent (fake runner): attest+verify, seal the payload to the attested
// channel key, POST it, and pull back a result sealed to dispatcher's result key.
func TestConfidentialExchange_SealedRoundTrip(t *testing.T) {
	signKey, keys := maaSigningKey(t)

	var gotPayload runPayload
	agent, err := newConfidentialAgent(agentConfig{
		fetchToken: tokenMinter(t, signKey),
		runner: func(_ context.Context, p runPayload) runResult {
			gotPayload = p
			return runResult{ExitCode: 0, Stdout: []byte("trained on " + string(p.DotEnv))}
		},
	})
	require.NoError(t, err)
	srv := httptest.NewServer(agent.handler())
	t.Cleanup(srv.Close)

	// 1. Attest + verify through the real attester (generates its own nonce).
	att := &csAttester{keys: keys, isReady: true, fetch: csEndpointFetch(srv.URL)}
	res, err := att.Verify(context.Background(), &VMInfo{}, "", "",
		types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{csDigest}})
	require.NoError(t, err)
	require.True(t, res.Verified, res.Verdict)
	require.NotEmpty(t, res.ChannelKey, "a verified result must carry the bound channel key to seal to")

	// 2. Seal a payload to the attested key, run it, pull back the sealed result.
	payload := runPayload{Command: []string{"python", "train.py"}, DotEnv: []byte("SECRET=1")}
	result, err := runSealedExchange(context.Background(), srv.URL, res.ChannelKey, payload)
	require.NoError(t, err)

	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, "trained on SECRET=1", string(result.Stdout))
	assert.Equal(t, []string{"python", "train.py"}, gotPayload.Command, "the agent must have opened the sealed command")
	assert.NotEmpty(t, gotPayload.ResultPubKey, "dispatcher must have handed the agent a key to seal the result to")
}

// TestConfidentialAgent_RejectsUnsealablePayload: a payload not sealed to the
// agent's key must fail to open (AEAD), not run.
func TestConfidentialAgent_RejectsUnsealablePayload(t *testing.T) {
	signKey, _ := maaSigningKey(t)
	ran := false
	agent, err := newConfidentialAgent(agentConfig{
		fetchToken: tokenMinter(t, signKey),
		runner:     func(context.Context, runPayload) runResult { ran = true; return runResult{} },
	})
	require.NoError(t, err)
	srv := httptest.NewServer(agent.handler())
	t.Cleanup(srv.Close)

	// Seal to a DIFFERENT key than the agent's — the agent can't open it.
	wrongPub, _, err := newChannelKeypair()
	require.NoError(t, err)
	_, err = runSealedExchange(context.Background(), srv.URL, wrongPub, runPayload{Command: []string{"x"}})
	require.Error(t, err)
	assert.False(t, ran, "the agent must not run a payload it could not open")
}
