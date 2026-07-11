package agent

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubAttest is a trivial attestation function: the sealed exchange does not
// verify the token (that is the dispatcher-side verifier's job), so a placeholder
// suffices to drive the agent's payload/result handling.
func stubAttest(context.Context, []byte, []byte) (string, error) { return "stub-token", nil }

// TestAgent_RejectsUnsealablePayload: a payload not sealed to the agent's channel
// key must fail to open (AEAD) and never run.
func TestAgent_RejectsUnsealablePayload(t *testing.T) {
	ran := false
	ag, err := NewAgent(stubAttest, func(context.Context, Payload) Result { ran = true; return Result{} })
	require.NoError(t, err)
	srv := httptest.NewServer(ag.Handler())
	t.Cleanup(srv.Close)

	// Seal to a DIFFERENT key than the agent's — the agent can't open it.
	wrongPub, _, err := newChannelKeypair()
	require.NoError(t, err)
	_, err = RunSealedExchange(context.Background(), srv.URL, wrongPub, Payload{Command: []string{"x"}})
	require.Error(t, err)
	assert.False(t, ran, "the agent must not run a payload it could not open")
}
