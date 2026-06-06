package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
)

// MCPServer exposes the planner's ToolRegistry over the Model Context Protocol
// (JSON-RPC 2.0 over HTTP). aitelier's /v1/agent passes its URL to claude-code
// via --mcp-config, and the agent invokes our Go-side tools through it.
type MCPServer struct {
	registry *ToolRegistry

	listener net.Listener
	server   *http.Server
	serveErr chan error

	mu   sync.Mutex
	spec *types.WorkloadSpec // captured after inspect_workload so evaluate_all_targets can use it
}

func NewMCPServer(registry *ToolRegistry) *MCPServer {
	return &MCPServer{registry: registry}
}

func (s *MCPServer) Start() error {
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
	return "http://" + s.listener.Addr().String()
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
)

func (s *MCPServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: rpcParseError, Message: "parse error"}})
		return
	}

	// Serialize all dispatch() calls: inspect_workload writes shared spec that
	// evaluate_all_targets reads. Concurrent requests must not see a torn view.
	s.mu.Lock()
	result, rpcErr := s.dispatch(req.Method, req.Params)
	s.mu.Unlock()

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

// dispatch must be called with s.mu held.
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

// toolsCall must be called with s.mu held.
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

	result := s.registry.Execute(ToolCall{Name: callParams.Name, Input: callParams.Arguments}, s.spec)

	if callParams.Name == "inspect_workload" && result.Error == "" {
		if ws, ok := result.Result.(types.WorkloadSpec); ok {
			s.spec = &ws
		}
	}

	if result.Error != "" {
		return toolErrorResult(result.Error)
	}

	payload, err := json.Marshal(result.Result)
	if err != nil {
		return toolErrorResult("cannot serialize tool result: " + err.Error())
	}

	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(payload)}},
		"isError": false,
	}
}

func toolErrorResult(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}
