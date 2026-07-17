package agent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unixTokenServer starts an httptest server bound to a unix socket (the shape of
// the Confidential Space container-launcher teeserver) and returns its path.
func unixTokenServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "teeserver.sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(handler)
	require.NoError(t, srv.Listener.Close()) // drop the default TCP listener
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return sock
}

func TestRequestAttestationToken_ReturnsJWT(t *testing.T) {
	sock := unixTokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "header.payload.sig\n")
	})
	tok, err := requestAttestationToken(context.Background(), sock, tokenRequest{
		Audience: "dispatcher", Nonces: []string{"abcd"},
	})
	require.NoError(t, err)
	assert.Equal(t, "header.payload.sig", tok, "returns the raw JWT, trimmed")
}

func TestRequestAttestationToken_SendsOIDCRequest(t *testing.T) {
	var got tokenRequest
	var gotPath, gotMethod string
	sock := unixTokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, "t")
	})
	_, err := requestAttestationToken(context.Background(), sock, tokenRequest{
		Audience: "dispatcher", Nonces: []string{"deadbeef", "cafe"},
	})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/v1/token", gotPath)
	assert.Equal(t, "OIDC", got.TokenType, "the verifier consumes the OIDC/EAT JWT form")
	assert.Equal(t, "dispatcher", got.Audience)
	assert.Equal(t, []string{"deadbeef", "cafe"}, got.Nonces)
}

func TestRequestAttestationToken_Non200Errors(t *testing.T) {
	sock := unixTokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unknown audience", http.StatusBadRequest)
	})
	_, err := requestAttestationToken(context.Background(), sock, tokenRequest{Audience: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "unknown audience")
}
