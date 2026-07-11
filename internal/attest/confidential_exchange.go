package attest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// The sealed exchange is how a Confidential Space run moves secrets and results
// across the untrusted TCP channel between dispatcher and the in-TEE agent
// (docs/confidential-space-execution.md). Everything dispatcher sends is HPKE-
// sealed to the agent's attested channel key; everything the agent returns is
// sealed to a fresh dispatcher result key. The channel itself is never trusted —
// the attestation binding and the sealing are what make it safe (R9).

// attestResponse is the agent's GET /attest body: the Google-signed CS token
// (binding the run nonce and SHA-256(channel key)) and the agent's channel
// public key (X25519) dispatcher seals to.
type attestResponse struct {
	Token      string `json:"token"`
	ChannelKey []byte `json:"channel_key"`
}

// Payload is what dispatcher seals to the agent's channel key and POSTs to
// /payload. []byte fields are base64 in JSON.
type Payload struct {
	Command      []string `json:"command"`
	DotEnv       []byte   `json:"dotenv,omitempty"`
	SourceTarGz  []byte   `json:"source_tar_gz,omitempty"`
	Outputs      []string `json:"outputs,omitempty"`
	ResultPubKey []byte   `json:"result_pubkey"` // the agent seals its result to this
}

// Result is what the agent seals back (to Payload.ResultPubKey) and serves
// from /result once the workload has finished.
type Result struct {
	ExitCode     int    `json:"exit_code"`
	Stdout       []byte `json:"stdout,omitempty"`
	Stderr       []byte `json:"stderr,omitempty"`
	OutputsTarGz []byte `json:"outputs_tar_gz,omitempty"`
}

// csEndpointFetch is a csFetch that obtains attestation evidence from the in-TEE
// agent's /attest endpoint over HTTP (the untrusted channel), passing the run
// nonce. It replaces the placeholder fetch and is what a live CS adapter wires
// into csAttester.
func csEndpointFetch(baseURL string) csFetch {
	return func(ctx context.Context, nonce []byte) (csEvidence, error) {
		u := baseURL + "/attest?nonce=" + url.QueryEscape(hex.EncodeToString(nonce))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return csEvidence{}, err
		}
		resp, err := csHTTPClient().Do(req)
		if err != nil {
			return csEvidence{}, fmt.Errorf("attest fetch: %w", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			return csEvidence{}, fmt.Errorf("attest fetch failed: %d: %s", resp.StatusCode, bytes.TrimSpace(body))
		}
		var ar attestResponse
		if err := json.Unmarshal(body, &ar); err != nil {
			return csEvidence{}, fmt.Errorf("parse attest response: %w", err)
		}
		return csEvidence{token: ar.Token, channelKey: ar.ChannelKey}, nil
	}
}

// RunSealedExchange seals payload to the attested channel key, POSTs it to the
// agent, polls /result, and opens the sealed result with a fresh dispatcher
// result key. Called only after the attestation over channelKey has verified.
func RunSealedExchange(ctx context.Context, baseURL string, channelKey []byte, payload Payload) (Result, error) {
	resultPub, resultPriv, err := newChannelKeypair()
	if err != nil {
		return Result{}, err
	}
	payload.ResultPubKey = resultPub

	plain, err := json.Marshal(payload)
	if err != nil {
		return Result{}, err
	}
	sealed, err := sealToChannelKey(channelKey, plain)
	if err != nil {
		return Result{}, fmt.Errorf("seal payload: %w", err)
	}

	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/payload", bytes.NewReader(sealed))
	if err != nil {
		return Result{}, err
	}
	postReq.Header.Set("Content-Type", "application/octet-stream")
	postResp, err := csHTTPClient().Do(postReq)
	if err != nil {
		return Result{}, fmt.Errorf("post payload: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(postResp.Body, 1<<20))
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusAccepted && postResp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("agent rejected payload: %d: %s", postResp.StatusCode, bytes.TrimSpace(body))
	}

	return pollSealedResult(ctx, baseURL, resultPriv)
}

// pollSealedResult polls /result until the agent returns a sealed result (200);
// 202 means the workload is still running. Opens the result with resultPriv.
func pollSealedResult(ctx context.Context, baseURL string, resultPriv []byte) (Result, error) {
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/result", nil)
		if err != nil {
			return Result{}, err
		}
		resp, err := csHTTPClient().Do(req)
		if err != nil {
			return Result{}, fmt.Errorf("poll result: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			plain, err := openSealed(resultPriv, body)
			if err != nil {
				return Result{}, fmt.Errorf("open sealed result: %w", err)
			}
			var r Result
			if err := json.Unmarshal(plain, &r); err != nil {
				return Result{}, fmt.Errorf("parse result: %w", err)
			}
			return r, nil
		case http.StatusAccepted:
			select {
			case <-ctx.Done():
				return Result{}, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		default:
			return Result{}, fmt.Errorf("result poll failed: %d: %s", resp.StatusCode, bytes.TrimSpace(body))
		}
	}
}

func csHTTPClient() *http.Client { return &http.Client{Timeout: 60 * time.Second} }
