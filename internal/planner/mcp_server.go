package planner

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
)

// MCPServer exposes the planner's ToolRegistry over the Model Context Protocol
// (JSON-RPC 2.0 over HTTP). aitelier's /v1/chat/completions receives this URL
// in the aitelier.mcp_servers block and forwards it to the inner agent, which
// invokes our Go-side tools through it.
type MCPServer struct {
	registry *ToolRegistry

	listener net.Listener
	server   *http.Server
	serveErr chan error
	token    string
	tokenErr error

	mu   sync.Mutex
	spec *types.WorkloadSpec // captured after inspect_workload so evaluate_all_targets can use it
}

func NewMCPServer(registry *ToolRegistry) *MCPServer {
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	return &MCPServer{
		registry: registry,
		token:    base64.RawURLEncoding.EncodeToString(raw),
		tokenErr: err,
	}
}

func (s *MCPServer) Start() error {
	if s.tokenErr != nil {
		return fmt.Errorf("generate mcp authentication token: %w", s.tokenErr)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("mcp server listen: %w", err)
	}
	s.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	s.serveErr = make(chan error, 1)
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.serveErr <- err
			log.Printf("mcp server exited: %v", err)
		}
		close(s.serveErr)
	}()
	return nil
}

func (s *MCPServer) Stop() error {
	if s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *MCPServer) URL() string {
	if s.listener == nil {
		return ""
	}
	return "http://" + s.listener.Addr().String() + "?token=" + s.token
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const (
	mcpProtocolVersion = "2024-11-05"
	rpcParseError      = -32700
	rpcMethodNotFound  = -32601
	maxMCPRequestBytes = 1 << 20
)

func (s *MCPServer) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// Accept the session token via an Authorization: Bearer header as well as the
	// URL query. The header keeps the token out of access logs (where query strings
	// commonly land); the query remains the working default until aitelier is
	// confirmed to forward per-MCP-server headers to the inner agent.
	provided := r.URL.Query().Get("token")
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		provided = strings.TrimPrefix(h, "Bearer ")
	}
	if len(provided) != len(s.token) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMCPRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: rpcParseError, Message: "parse error"}})
		return
	}

	// The shared spec that inspect_workload writes and later tools read is guarded
	// inside toolsCall (only around the pointer read/write), NOT across the whole
	// dispatch — holding the lock over a filesystem-bound InspectCodebase would
	// serialize every concurrent tool call and risk the server's WriteTimeout.
	result, rpcErr := s.dispatch(req.Method, req.Params)

	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	if isNotification {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}
	writeRPC(w, resp)
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// dispatch routes an RPC method. The shared spec it touches is guarded inside
// toolsCall, so this need not be called under s.mu.
func (s *MCPServer) dispatch(method string, params json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": mcpServerName, "version": "0.1.0"},
		}, nil

	case "notifications/initialized":
		return nil, nil

	case "tools/list":
		return map[string]any{"tools": s.toolList()}, nil

	case "tools/call":
		return s.toolsCall(params), nil

	default:
		return nil, &rpcError{Code: rpcMethodNotFound, Message: "method not found: " + method}
	}
}

func (s *MCPServer) toolList() []map[string]any {
	defs := s.registry.Definitions()
	out := make([]map[string]any, len(defs))
	for i, d := range defs {
		out[i] = map[string]any{
			"name":        d.Name,
			"description": d.Description,
			"inputSchema": d.Parameters,
		}
	}
	return out
}

// toolsCall runs one tool. It guards the shared spec pointer with s.mu only
// around the read/write, not across the tool Execute.
func (s *MCPServer) toolsCall(params json.RawMessage) map[string]any {
	var callParams struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &callParams); err != nil {
		return toolErrorResult("invalid tool call params: " + err.Error())
	}
	if len(callParams.Arguments) == 0 {
		callParams.Arguments = json.RawMessage("{}")
	}

	// Read the shared spec under the lock, then run the (possibly filesystem-bound)
	// tool WITHOUT the lock so a slow scan doesn't block concurrent tool calls.
	s.mu.Lock()
	spec := s.spec
	s.mu.Unlock()

	result := s.registry.Execute(ToolCall{Name: callParams.Name, Input: callParams.Arguments}, spec)

	payloadResult := result.Result
	if callParams.Name == "inspect_workload" && result.Error == "" {
		if ws, ok := result.Result.(types.WorkloadSpec); ok {
			s.mu.Lock()
			s.spec = &ws
			s.mu.Unlock()
			payloadResult = redactWorkloadForAI(ws)
		}
	}

	if result.Error != "" {
		return toolErrorResult(result.Error)
	}

	payload, err := json.Marshal(payloadResult)
	if err != nil {
		return toolErrorResult("cannot serialize tool result: " + err.Error())
	}

	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(payload)}},
		"isError": false,
	}
}

// redactWorkloadForAI keeps the full inspected spec inside dispatcher for
// feasibility/policy evaluation while removing operator identity, filesystem
// layout, command/env values, and secret/data identifiers from the MCP payload.
// The model still sees counts and kinds, which is enough to reason about policy.
func redactWorkloadForAI(ws types.WorkloadSpec) types.WorkloadSpec {
	ws.Name = "workload"
	ws.Source.Path = "."
	ws.Command = nil
	ws.Env = nil
	// Deep-copy the Secrets/Data slices before redacting: ws is a value copy but
	// its slices share their backing arrays with the retained s.spec, so in-place
	// edits would silently corrupt the real spec that evaluate_all_targets scores.
	ws.Secrets = append([]types.SecretRef(nil), ws.Secrets...)
	for i := range ws.Secrets {
		ws.Secrets[i].Name = "[redacted]"
		ws.Secrets[i].Location = "[redacted]"
	}
	ws.Data = append([]types.DataRequirement(nil), ws.Data...)
	for i := range ws.Data {
		ws.Data[i].Location = "[redacted]"
		ws.Data[i].Details = ""
	}
	return ws
}

func toolErrorResult(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}
