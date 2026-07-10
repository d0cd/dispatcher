package cloudvm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

// confidentialAgent is the in-TEE side of a Confidential Space run — the measured
// entrypoint baked into the workload image (its digest is the attested identity).
// It holds the channel keypair (private key never leaves the TEE), serves
// attestation evidence, opens the sealed payload, runs the workload, and serves a
// sealed result. dispatcher talks to it over the untrusted TCP channel; the
// attestation binding + sealing are what make that safe (R9).
type confidentialAgent struct {
	pub, priv []byte
	cfg       agentConfig

	mu        sync.Mutex
	started   bool
	done      bool
	resultPub []byte
	result    runResult
}

type agentConfig struct {
	// fetchToken obtains an attestation token binding the given nonces. Defaults
	// to the container-launcher teeserver socket; tests inject a stub.
	fetchToken func(ctx context.Context, nonces []string) (string, error)
	// runner executes the opened payload's workload and returns its result. The
	// default exec runner ships with the agent binary; the core is injectable.
	runner   func(ctx context.Context, p runPayload) runResult
	audience string
}

func newConfidentialAgent(cfg agentConfig) (*confidentialAgent, error) {
	if cfg.fetchToken == nil {
		cfg.fetchToken = func(ctx context.Context, nonces []string) (string, error) {
			return requestAttestationToken(ctx, csTeeserverSocket, tokenRequest{Audience: cfg.audience, Nonces: nonces})
		}
	}
	pub, priv, err := newChannelKeypair()
	if err != nil {
		return nil, err
	}
	return &confidentialAgent{pub: pub, priv: priv, cfg: cfg}, nil
}

func (a *confidentialAgent) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/attest", a.handleAttest)
	mux.HandleFunc("/payload", a.handlePayload)
	mux.HandleFunc("/result", a.handleResult)
	return mux
}

// handleAttest fetches a token binding [runNonce, SHA-256(channelPub)] and
// returns it with the channel public key — the evidence dispatcher verifies and
// seals to.
func (a *confidentialAgent) handleAttest(w http.ResponseWriter, r *http.Request) {
	nonceHex := r.URL.Query().Get("nonce")
	if nonceHex == "" {
		http.Error(w, "missing nonce", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(a.pub)
	nonces := []string{nonceHex, hex.EncodeToString(sum[:])}
	token, err := a.cfg.fetchToken(r.Context(), nonces)
	if err != nil {
		http.Error(w, "fetch token: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, attestResponse{Token: token, ChannelKey: a.pub})
}

// handlePayload opens the sealed payload with the channel private key and starts
// the workload. A payload that doesn't open (not sealed to this TEE) is rejected
// and never runs.
func (a *confidentialAgent) handlePayload(w http.ResponseWriter, r *http.Request) {
	if a.cfg.runner == nil {
		http.Error(w, "no runner configured", http.StatusNotImplemented)
		return
	}
	sealed, err := io.ReadAll(io.LimitReader(r.Body, 256<<20))
	if err != nil {
		http.Error(w, "read payload", http.StatusBadRequest)
		return
	}
	plain, err := openSealed(a.priv, sealed)
	if err != nil {
		http.Error(w, "cannot open sealed payload (not sealed to this TEE)", http.StatusBadRequest)
		return
	}
	var p runPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		http.Error(w, "parse payload", http.StatusBadRequest)
		return
	}
	if len(p.ResultPubKey) == 0 {
		http.Error(w, "payload missing result_pubkey", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		http.Error(w, "payload already accepted", http.StatusConflict)
		return
	}
	a.started = true
	a.resultPub = p.ResultPubKey
	a.mu.Unlock()

	go func() {
		res := a.cfg.runner(context.Background(), p)
		a.mu.Lock()
		a.result, a.done = res, true
		a.mu.Unlock()
	}()
	w.WriteHeader(http.StatusAccepted)
}

// handleResult serves the workload result sealed to the payload's result key.
// 202 until the workload finishes, then 200 with the sealed result.
func (a *confidentialAgent) handleResult(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	done, res, resultPub := a.done, a.result, a.resultPub
	a.mu.Unlock()
	if !done {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	plain, err := json.Marshal(res)
	if err != nil {
		http.Error(w, "marshal result", http.StatusInternalServerError)
		return
	}
	sealed, err := sealToChannelKey(resultPub, plain)
	if err != nil {
		http.Error(w, "seal result", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
