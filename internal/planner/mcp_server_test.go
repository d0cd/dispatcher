package planner

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rpc sends a JSON-RPC 2.0 request to the server and returns the decoded response.
func rpc(t *testing.T, url, method string, id any, params any) map[string]any {
	t.Helper()
	body := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}
	if id != nil {
		body["id"] = id
	}
	buf, err := json.Marshal(body)
	require.NoError(t, err)

	resp, err := http.Post(url, "application/json", bytes.NewReader(buf))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Notifications (no id) return 202 and no body
	if id == nil {
		assert.Equal(t, http.StatusAccepted, resp.StatusCode)
		return nil
	}

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestMCPServer_LifecycleAndURL(t *testing.T) {
	tools, _ := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	assert.True(t, strings.HasPrefix(srv.URL(), "http://127.0.0.1:"))
	assert.NotEqual(t, "http://127.0.0.1:0", srv.URL())
	parsed, err := url.Parse(srv.URL())
	require.NoError(t, err)
	assert.Len(t, parsed.Query().Get("token"), 43)
}

func TestMCPServer_RejectsRequestsWithoutSessionToken(t *testing.T) {
	tools, _ := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	u, err := url.Parse(srv.URL())
	require.NoError(t, err)
	u.RawQuery = ""
	resp, err := http.Post(u.String(), "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// A present-but-wrong token must be rejected too — a missing-token-only check
	// would pass even if the constant-time compare (the real auth boundary) broke.
	u.RawQuery = "token=" + strings.Repeat("A", 43)
	wrong, err := http.Post(u.String(), "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	require.NoError(t, err)
	defer wrong.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, wrong.StatusCode, "a wrong token must be rejected")
}

func TestMCPServer_RejectsOversizedBody(t *testing.T) {
	tools, _ := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	resp, err := http.Post(srv.URL(), "application/json", strings.NewReader(strings.Repeat("x", maxMCPRequestBytes+1)))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

func TestMCPServer_Initialize(t *testing.T) {
	tools, _ := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	resp := rpc(t, srv.URL(), "initialize", 1, map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "0"},
	})

	assert.Equal(t, "2.0", resp["jsonrpc"])
	assert.Nil(t, resp["error"])
	result := resp["result"].(map[string]any)
	assert.Equal(t, "2024-11-05", result["protocolVersion"])
	caps := result["capabilities"].(map[string]any)
	_, hasTools := caps["tools"]
	assert.True(t, hasTools, "server must advertise tools capability")
	info := result["serverInfo"].(map[string]any)
	assert.Equal(t, "dispatcher", info["name"])
}

func TestMCPServer_NotificationInitialized(t *testing.T) {
	tools, _ := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	// Notification (no id) — should return 202 No Content, no body.
	rpc(t, srv.URL(), "notifications/initialized", nil, map[string]any{})
}

func TestMCPServer_ToolsList(t *testing.T) {
	tools, _ := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	resp := rpc(t, srv.URL(), "tools/list", 2, map[string]any{})
	assert.Nil(t, resp["error"])
	result := resp["result"].(map[string]any)
	toolList := result["tools"].([]any)
	assert.Len(t, toolList, 5)

	names := make(map[string]bool)
	for _, raw := range toolList {
		tool := raw.(map[string]any)
		names[tool["name"].(string)] = true
		assert.NotEmpty(t, tool["description"])
		_, hasSchema := tool["inputSchema"]
		assert.True(t, hasSchema, "tool %s missing inputSchema", tool["name"])
	}
	assert.True(t, names["inspect_workload"])
	assert.True(t, names["evaluate_all_targets"])
	assert.True(t, names["find_cheapest_instances"])
	assert.True(t, names["get_run_history"])
	assert.True(t, names["inspect_run"])
}

func TestMCPServer_ToolsCall_InspectWorkload(t *testing.T) {
	tools, dir := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	resp := rpc(t, srv.URL(), "tools/call", 3, map[string]any{
		"name":      "inspect_workload",
		"arguments": map[string]any{"path": dir},
	})
	assert.Nil(t, resp["error"], "rpc error: %v", resp["error"])
	result := resp["result"].(map[string]any)
	assert.NotEqual(t, true, result["isError"])

	content := result["content"].([]any)
	require.Len(t, content, 1)
	textBlock := content[0].(map[string]any)
	assert.Equal(t, "text", textBlock["type"])
	// Inspecting a Python workload — the JSON payload should mention "python" somewhere
	payload := textBlock["text"].(string)
	assert.Contains(t, strings.ToLower(payload), "python")
	assert.NotContains(t, payload, dir, "MCP payload must not expose the operator's absolute workload path")
}

// Crucial: evaluate_all_targets needs the spec from a prior inspect_workload call.
// The MCP server tracks it across calls within its lifetime.
func TestMCPServer_ToolsCall_EvaluateAfterInspect(t *testing.T) {
	tools, dir := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	rpc(t, srv.URL(), "tools/call", 4, map[string]any{
		"name":      "inspect_workload",
		"arguments": map[string]any{"path": dir},
	})

	resp := rpc(t, srv.URL(), "tools/call", 5, map[string]any{
		"name":      "evaluate_all_targets",
		"arguments": map[string]any{},
	})
	assert.Nil(t, resp["error"])
	result := resp["result"].(map[string]any)
	assert.NotEqual(t, true, result["isError"])
}

func TestMCPServer_ToolsCall_EvaluateWithoutInspect(t *testing.T) {
	tools, _ := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	resp := rpc(t, srv.URL(), "tools/call", 6, map[string]any{
		"name":      "evaluate_all_targets",
		"arguments": map[string]any{},
	})
	// Should surface as a tool-level error in the result, not an RPC error.
	assert.Nil(t, resp["error"])
	result := resp["result"].(map[string]any)
	assert.Equal(t, true, result["isError"])
	content := result["content"].([]any)
	textBlock := content[0].(map[string]any)
	assert.Contains(t, textBlock["text"].(string), "inspect_workload first")
}

func TestMCPServer_ToolsCall_UnknownTool(t *testing.T) {
	tools, _ := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	resp := rpc(t, srv.URL(), "tools/call", 7, map[string]any{
		"name":      "nope",
		"arguments": map[string]any{},
	})
	assert.Nil(t, resp["error"])
	result := resp["result"].(map[string]any)
	assert.Equal(t, true, result["isError"])
}

func TestMCPServer_UnknownMethod(t *testing.T) {
	tools, _ := setupTestEnv(t)
	srv := NewMCPServer(tools)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	resp := rpc(t, srv.URL(), "resources/list", 8, map[string]any{})
	errObj := resp["error"].(map[string]any)
	// JSON-RPC reserves -32601 for "Method not found"
	assert.Equal(t, float64(-32601), errObj["code"])
}
