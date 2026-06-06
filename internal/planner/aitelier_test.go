package planner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubAitelier serves a minimal OpenAI-shaped aitelier surface for tests:
// /v1/chat/completions + /v1/discovery + /v1/runs/* + /v1/health.
type stubAitelier struct {
	server         *httptest.Server
	requests       []map[string]any
	requestHeaders []http.Header

	// Response shape: the stub returns this body verbatim for /v1/chat/completions.
	// Defaults to a successful OpenAI ChatCompletion.
	response map[string]any
	// status overrides the default 200 status code on /v1/chat/completions.
	status int

	healthOK      bool
	discoveryBody map[string]any

	// in-flight + cancel coordination
	mu             sync.Mutex
	chatBlock      chan struct{} // close to release pending /v1/chat/completions calls
	activeRuns     []string
	cancelledRuns  []string
	cancelRequests int

	// Event timeline returned by /v1/runs/{id}/events
	events []map[string]any
}

func newStubAitelier(t *testing.T) *stubAitelier {
	t.Helper()
	stub := &stubAitelier{
		healthOK: true,
		status:   http.StatusOK,
		response: map[string]any{
			"id":      "chatcmpl-stub",
			"object":  "chat.completion",
			"created": 0,
			"model":   "agent:claude",
			"choices": []map[string]any{{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": `{"explanation":"stub recommendation"}`,
				},
				"finish_reason": "stop",
			}},
			"aitelier_run_id": "stub_run_1",
		},
		discoveryBody: map[string]any{
			"capabilities": map[string]any{"agent": map[string]any{"available": true}},
			"dependencies": map[string]any{
				"sandbox_agent": map[string]any{"reachable": true, "agents": []string{"claude", "codex"}},
				"litellm":       map[string]any{"reachable": true},
			},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if !stub.healthOK {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"test"}`))
	})
	mux.HandleFunc("/v1/discovery", func(w http.ResponseWriter, r *http.Request) {
		if !stub.healthOK {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stub.discoveryBody)
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		stub.mu.Lock()
		stub.requests = append(stub.requests, req)
		stub.requestHeaders = append(stub.requestHeaders, r.Header.Clone())
		block := stub.chatBlock
		stub.mu.Unlock()
		if block != nil {
			select {
			case <-block:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stub.status)
		_ = json.NewEncoder(w).Encode(stub.response)
	})
	mux.HandleFunc("/v1/runs/active", func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		ids := append([]string{}, stub.activeRuns...)
		stub.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": ids})
	})
	mux.HandleFunc("/v1/runs/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cancel") {
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/runs/"), "/cancel")
			stub.mu.Lock()
			stub.cancelRequests++
			stub.cancelledRuns = append(stub.cancelledRuns, id)
			stub.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"run_id": id, "cancelled": true})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/events") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(stub.events)
			return
		}
		http.NotFound(w, r)
	})
	stub.server = httptest.NewServer(mux)
	t.Cleanup(stub.server.Close)
	return stub
}

func TestAtelierBackend_CheckAvailable_OK(t *testing.T) {
	stub := newStubAitelier(t)
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL})
	require.NoError(t, b.CheckAvailable(context.Background()))
}

func TestAtelierBackend_CheckAvailable_DownReturnsError(t *testing.T) {
	stub := newStubAitelier(t)
	stub.healthOK = false
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL})
	err := b.CheckAvailable(context.Background())
	require.Error(t, err)
}

func TestAtelierBackend_Chat_SendsChatCompletionWithAitelierBlock(t *testing.T) {
	stub := newStubAitelier(t)
	tools, _ := setupTestEnv(t)
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL, ToolRegistry: tools})

	resp, err := b.Chat(context.Background(), []Message{
		{Role: "system", Content: "system prompt here"},
		{Role: "user", Content: "Plan execution for /tmp/test"},
	}, tools.Definitions())
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Len(t, stub.requests, 1)
	req := stub.requests[0]

	// Model routes through aitelier as "agent:<backend>".
	assert.Equal(t, "agent:claude", req["model"])

	// OpenAI messages array with the system + user roles preserved.
	msgs, ok := req["messages"].([]any)
	require.True(t, ok)
	require.Len(t, msgs, 2)
	assert.Equal(t, "system", msgs[0].(map[string]any)["role"])
	assert.Equal(t, "system prompt here", msgs[0].(map[string]any)["content"])
	assert.Equal(t, "user", msgs[1].(map[string]any)["role"])

	// Agent options ride in the aitelier namespace at the top level.
	ait, ok := req["aitelier"].(map[string]any)
	require.True(t, ok, "aitelier block missing")
	servers, ok := ait["mcp_servers"].([]any)
	require.True(t, ok)
	require.Len(t, servers, 1)
	srv := servers[0].(map[string]any)
	assert.Equal(t, "dispatcher", srv["name"])
	assert.Equal(t, "http", srv["transport"])
	assert.True(t, strings.HasPrefix(srv["url"].(string), "http://127.0.0.1:"))

	allowlist, ok := ait["tool_allowlist"].([]any)
	require.True(t, ok)
	allowSet := make(map[string]bool)
	for _, a := range allowlist {
		allowSet[a.(string)] = true
	}
	assert.True(t, allowSet["mcp__dispatcher__inspect_workload"])
	assert.True(t, allowSet["mcp__dispatcher__evaluate_all_targets"])
	assert.True(t, allowSet["mcp__dispatcher__find_cheapest_instances"])
	assert.True(t, allowSet["mcp__dispatcher__get_run_history"])

	// response_format rides at the top level (OpenAI shape).
	rf, ok := req["response_format"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "json_schema", rf["type"])
	schema := rf["schema"].(map[string]any)
	props := schema["properties"].(map[string]any)
	for _, key := range []string{"explanation", "recommendation", "alternatives", "rejected", "risks", "approvals", "suggestions", "toolsUsed"} {
		_, present := props[key]
		assert.True(t, present, "schema missing %q", key)
	}
}

func TestAtelierBackend_Chat_AgentWithInnerLLMRoutes(t *testing.T) {
	stub := newStubAitelier(t)
	tools, _ := setupTestEnv(t)
	b := NewAtelierBackend(AtelierConfig{
		BaseURL:      stub.server.URL,
		Agent:        "claude",
		Model:        "claude-sonnet-4-5",
		ToolRegistry: tools,
	})

	_, err := b.Chat(context.Background(), []Message{{Role: "user", Content: "x"}}, tools.Definitions())
	require.NoError(t, err)
	assert.Equal(t, "agent:claude/claude-sonnet-4-5", stub.requests[0]["model"])
}

func TestAtelierBackend_Chat_ReturnsContentFromFirstChoice(t *testing.T) {
	stub := newStubAitelier(t)
	tools, _ := setupTestEnv(t)
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL, ToolRegistry: tools})

	resp, err := b.Chat(context.Background(), []Message{
		{Role: "user", Content: "x"},
	}, tools.Definitions())
	require.NoError(t, err)
	assert.Contains(t, resp.Content, "stub recommendation")
}

// When aitelier returns the server-side fence-stripped JSON in
// `choices[0].message.aitelier_parsed`, AtelierBackend prefers it over the raw
// `content` field so downstream consumers get pre-parsed JSON.
func TestAtelierBackend_Chat_PrefersAitelierParsedOverContent(t *testing.T) {
	stub := newStubAitelier(t)
	stub.response = map[string]any{
		"id":      "x",
		"object":  "chat.completion",
		"created": 0,
		"model":   "agent:claude",
		"choices": []map[string]any{{
			"index": 0,
			"message": map[string]any{
				"role":            "assistant",
				"content":         "```json\n{\"explanation\":\"parsed\"}\n```",
				"aitelier_parsed": map[string]any{"explanation": "parsed"},
			},
			"finish_reason": "stop",
		}},
	}
	tools, _ := setupTestEnv(t)
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL, ToolRegistry: tools})
	resp, err := b.Chat(context.Background(), []Message{{Role: "user", Content: "x"}}, tools.Definitions())
	require.NoError(t, err)
	assert.Equal(t, `{"explanation":"parsed"}`, resp.Content)
}

func TestAtelierBackend_Chat_SurfacesAitelierError(t *testing.T) {
	stub := newStubAitelier(t)
	stub.status = http.StatusBadGateway
	stub.response = map[string]any{
		"error": map[string]any{
			"type":    "ProviderError",
			"message": "something went wrong",
			"code":    "error",
		},
	}
	tools, _ := setupTestEnv(t)
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL, ToolRegistry: tools})

	_, err := b.Chat(context.Background(), []Message{
		{Role: "user", Content: "x"},
	}, tools.Definitions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ProviderError")
	assert.Contains(t, err.Error(), "something went wrong")
}

func TestAtelierBackend_CheckAvailable_RequiresSandboxReachable(t *testing.T) {
	stub := newStubAitelier(t)
	stub.discoveryBody = map[string]any{
		"capabilities": map[string]any{"agent": map[string]any{"available": false}},
		"dependencies": map[string]any{"sandbox_agent": map[string]any{"reachable": false}},
	}
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL})
	err := b.CheckAvailable(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sandbox")
}

func TestAtelierBackend_Chat_SendsCorrelationIDAndTraceTag(t *testing.T) {
	stub := newStubAitelier(t)
	tools, _ := setupTestEnv(t)
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL, ToolRegistry: tools})

	_, err := b.Chat(context.Background(), []Message{
		{Role: "system", Content: "s"},
		{Role: "user", Content: "u"},
	}, tools.Definitions())
	require.NoError(t, err)

	require.Len(t, stub.requestHeaders, 1)
	corr := stub.requestHeaders[0].Get("X-Correlation-Id")
	assert.NotEmpty(t, corr, "X-Correlation-Id must be set")
	assert.True(t, strings.HasPrefix(corr, "dispatcher-"), "correlation id should be namespaced to dispatcher")

	require.Len(t, stub.requests, 1)
	ait, _ := stub.requests[0]["aitelier"].(map[string]any)
	tag, _ := ait["trace_tag"].(string)
	assert.Equal(t, corr, tag, "trace_tag should match X-Correlation-Id")
}

func TestAtelierBackend_Chat_SendsAPIKeyWhenSet(t *testing.T) {
	stub := newStubAitelier(t)
	tools, _ := setupTestEnv(t)
	b := NewAtelierBackend(AtelierConfig{
		BaseURL:      stub.server.URL,
		APIKey:       "test-key",
		ToolRegistry: tools,
	})

	_, err := b.Chat(context.Background(), []Message{{Role: "user", Content: "x"}}, tools.Definitions())
	require.NoError(t, err)
	require.Len(t, stub.requestHeaders, 1)
	assert.Equal(t, "Bearer test-key", stub.requestHeaders[0].Get("Authorization"))
}

func TestAtelierBackend_Chat_CancelsAitelierRunsOnContextCancel(t *testing.T) {
	stub := newStubAitelier(t)
	stub.chatBlock = make(chan struct{})

	tools, _ := setupTestEnv(t)
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL, ToolRegistry: tools})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := b.Chat(ctx, []Message{{Role: "user", Content: "x"}}, tools.Definitions())
		done <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stub.mu.Lock()
		n := len(stub.requests)
		stub.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stub.mu.Lock()
	stub.activeRuns = []string{"2026-06-10T10-00-00_chat_agent"}
	stub.mu.Unlock()

	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Chat did not return after context cancel")
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stub.mu.Lock()
		n := stub.cancelRequests
		stub.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	assert.GreaterOrEqual(t, stub.cancelRequests, 1, "must POST /v1/runs/<id>/cancel when ctx is canceled")
	assert.Contains(t, stub.cancelledRuns, "2026-06-10T10-00-00_chat_agent")
}

func TestAtelierBackend_Chat_MapsCancelledErrorType(t *testing.T) {
	stub := newStubAitelier(t)
	stub.status = http.StatusBadRequest
	stub.response = map[string]any{
		"error": map[string]any{
			"type":    "Cancelled",
			"message": "Run was cancelled via POST /v1/runs/.../cancel",
			"code":    "error",
		},
	}
	tools, _ := setupTestEnv(t)
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL, ToolRegistry: tools})

	_, err := b.Chat(context.Background(), []Message{{Role: "user", Content: "x"}}, tools.Definitions())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAtelierCancelled), "Cancelled error_type should map to ErrAtelierCancelled")
}

// fetchToolNames hits /v1/runs/{id}/events to recover tool names since the
// OpenAI ChatCompletion shape doesn't surface inner-agent tool calls.
func TestAtelierBackend_Chat_FetchesToolNamesFromEvents(t *testing.T) {
	stub := newStubAitelier(t)
	stub.events = []map[string]any{
		{"kind": "start", "payload": map[string]any{}},
		{"kind": "tool_call", "payload": map[string]any{"tool": "mcp__dispatcher__inspect_workload"}},
		{"kind": "tool_call", "payload": map[string]any{"tool": "mcp__dispatcher__evaluate_all_targets"}},
		{"kind": "finish", "payload": map[string]any{}},
	}
	tools, _ := setupTestEnv(t)
	b := NewAtelierBackend(AtelierConfig{BaseURL: stub.server.URL, ToolRegistry: tools})

	resp, err := b.Chat(context.Background(), []Message{{Role: "user", Content: "x"}}, tools.Definitions())
	require.NoError(t, err)
	assert.Contains(t, resp.ToolsUsed, "mcp__dispatcher__inspect_workload")
	assert.Contains(t, resp.ToolsUsed, "mcp__dispatcher__evaluate_all_targets")
	assert.NotContains(t, resp.ToolsUsed, "start")
}
