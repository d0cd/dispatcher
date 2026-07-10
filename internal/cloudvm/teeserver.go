package cloudvm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// The Confidential Space container launcher exposes an attestation-token
// endpoint on a unix socket inside the guest. A workload POSTs a token request
// and receives a Google-signed OIDC/EAT token (a JWT) whose eat_nonce echoes the
// supplied nonces and whose submods.container.image_digest is the measured
// workload identity. This client runs INSIDE the CS guest (the measured agent),
// not in dispatcher — dispatcher only ever verifies the resulting token.
const (
	csTeeserverSocket = "/run/container_launcher/teeserver.sock"
	csTokenPath       = "/v1/token"
)

// tokenRequest is the teeserver token request body. Nonces are hex strings the
// service echoes in eat_nonce (freshness plus the channel-key binding).
type tokenRequest struct {
	Audience  string   `json:"audience"`
	TokenType string   `json:"token_type"`
	Nonces    []string `json:"nonces"`
}

// requestAttestationToken asks the container-launcher teeserver (over its unix
// socket) for an attestation token binding req.Nonces. TokenType is forced to
// OIDC — the EAT/JWT form dispatcher's verifier consumes. Returns the raw JWT.
func requestAttestationToken(ctx context.Context, socketPath string, req tokenRequest) (string, error) {
	req.TokenType = "OIDC"
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal token request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}

	// The host is ignored on a unix socket, but net/http still needs a
	// well-formed URL; "localhost" is the container-launcher convention.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+csTokenPath, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("teeserver token request: %w", err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read teeserver token: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("teeserver token request failed: %d: %s", resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
