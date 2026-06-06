package planner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/d0cd/dispatcher/internal/dlog"
	"github.com/d0cd/dispatcher/internal/types"
)

// ErrAtelierCancelled is returned when aitelier reports error_type=Cancelled,
// either because we asked it to (ctx cancel) or another caller did.
var ErrAtelierCancelled = errors.New("aitelier run cancelled")

// AtelierBackend implements Backend by calling aitelier's OpenAI-shaped
// /v1/chat/completions endpoint with `model: "agent:<backend>"`. aitelier
// delegates to claude-code (or another sandbox-agent backend), which drives a
// tool loop against a local MCP server (started here) that wraps the planner's
// ToolRegistry.
type AtelierBackend struct {
	baseURL  string
	agent    string // backend name (claude, codex, ...) — first segment of `model`
	model    string // optional inner LLM (e.g. "claude-sonnet-4-5") — second segment
	apiKey   string // optional Bearer token for hosted mode
	registry *ToolRegistry
	client   *http.Client

	// responseSchema is the JSON schema sent to aitelier as response_format.
	// Defaults to the plan schema; callers can override via SetResponseSchema
	// before invoking Diagnose/Audit so the inner agent isn't told to produce
	// PlanResult-shaped JSON for a non-plan flow.
	responseSchema *responseFormat
}

type AtelierConfig struct {
	BaseURL      string
	Agent        string // backend name; default "claude"
	Model        string // optional inner LLM; empty = backend default
	APIKey       string // optional Bearer key for hosted-mode aitelier
	ToolRegistry *ToolRegistry
}

func NewAtelierBackend(cfg AtelierConfig) *AtelierBackend {
	if cfg.BaseURL == "" {
		cfg.BaseURL = os.Getenv("AITELIER_URL")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:7777"
	}
	if cfg.Agent == "" {
		cfg.Agent = os.Getenv("AITELIER_AGENT")
	}
	if cfg.Agent == "" {
		cfg.Agent = "claude"
	}
	if cfg.Model == "" {
		cfg.Model = os.Getenv("AITELIER_MODEL")
	}
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("AITELIER_API_KEY")
	}

	return &AtelierBackend{
		baseURL:        cfg.BaseURL,
		agent:          cfg.Agent,
		model:          cfg.Model,
		apiKey:         cfg.APIKey,
		registry:       cfg.ToolRegistry,
		client:         &http.Client{Timeout: 5 * time.Minute},
		responseSchema: planResultResponseFormat(),
	}
}

// SetResponseSchema overrides the response_format sent to aitelier on the
// next Chat call. Pass nil to ask for free-form text. Audit/Diagnose use this
// so the inner agent isn't told to produce a PlanResult-shaped object when
// it's actually doing a different job.
func (a *AtelierBackend) SetResponseSchema(s *responseFormat) {
	a.responseSchema = s
}

// ResponseSchemaPlan exposes the plan schema so callers (Diagnose/Audit) can
// reset to the plan schema after temporarily overriding for another flow.
// Kept as a method rather than a constant because the schema is built lazily.
func ResponseSchemaPlan() *responseFormat { return planResultResponseFormat() }

// ResponseSchemaAudit returns the JSON schema for an AuditResult. Used by
// Audit() to tell aitelier "produce this shape, not PlanResult".
func ResponseSchemaAudit() *responseFormat { return auditResultResponseFormat() }

// ResponseSchemaDiagnose returns the JSON schema for a DiagnoseResult.
func ResponseSchemaDiagnose() *responseFormat { return diagnoseResultResponseFormat() }

// Agent returns the backend name (used for CLI display).
func (a *AtelierBackend) Agent() string { return a.agent }

// Model returns the inner LLM when set, else the backend name.
// Kept for backwards compat with callers that displayed Model() as the
// human-readable selector.
func (a *AtelierBackend) Model() string {
	if a.model != "" {
		return a.model
	}
	return a.agent
}

// modelString returns the OpenAI `model` field aitelier routes on, either
// "agent:<backend>" or "agent:<backend>/<inner-llm>".
func (a *AtelierBackend) modelString() string {
	if a.model == "" {
		return "agent:" + a.agent
	}
	return "agent:" + a.agent + "/" + a.model
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
	Aitelier       *aitelierOpts   `json:"aitelier,omitempty"`
}

// aitelierOpts mirrors /v1/schemas/aitelier_request — `additionalProperties: false`.
// Wall-clock timeouts ride on the HTTP client, not in the body.
type aitelierOpts struct {
	MCPServers    []mcpServerSpec `json:"mcp_servers,omitempty"`
	ToolAllowlist []string        `json:"tool_allowlist,omitempty"`
	MaxTurns      int             `json:"max_turns,omitempty"`
	TraceTag      string          `json:"trace_tag,omitempty"`
}

type mcpServerSpec struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`
	URL       string `json:"url"`
}

type responseFormat struct {
	Type   string         `json:"type"`
	Schema map[string]any `json:"schema,omitempty"`
	Strict bool           `json:"strict,omitempty"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Role             string `json:"role"`
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content,omitempty"`
			// aitelier-specific: server-side fence-stripped + parsed JSON when
			// response_format is json_object / json_schema.
			AitelierParsed any `json:"aitelier_parsed,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
		// aitelier-specific: "empty" when reasoning consumed the budget.
		AitelierExit string `json:"aitelier_exit,omitempty"`
	} `json:"choices"`
	AitelierRunID   string `json:"aitelier_run_id,omitempty"`
	AitelierTraceID string `json:"aitelier_trace_id,omitempty"`
	CorrelationID   string `json:"correlation_id,omitempty"`
	Usage           struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage,omitempty"`
}

type chatCompletionErrorBody struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
		Code    string `json:"code,omitempty"`
	} `json:"error"`
	AitelierRunID string `json:"aitelier_run_id,omitempty"`
}

type discoveryResponse struct {
	Dependencies struct {
		SandboxAgent struct {
			Reachable bool     `json:"reachable"`
			Agents    []string `json:"agents"`
		} `json:"sandbox_agent"`
	} `json:"dependencies"`
}

type activeRunsResponse struct {
	Active []string `json:"active"`
}

type runEvent struct {
	Kind    string         `json:"kind"`
	Payload map[string]any `json:"payload"`
}

// Chat runs one /v1/chat/completions call with model=agent:<backend>. The
// agent loop happens inside aitelier; the planner sees a single turn that
// returns the final structured plan with no follow-up tool calls.
func (a *AtelierBackend) Chat(ctx context.Context, messages []Message, tools []Tool) (*Message, error) {
	if a.registry == nil {
		return nil, fmt.Errorf("AtelierBackend requires a ToolRegistry — agent loop needs an MCP server")
	}

	mcp := NewMCPServer(a.registry)
	if err := mcp.Start(); err != nil {
		return nil, fmt.Errorf("start mcp server: %w", err)
	}
	defer func() { _ = mcp.Stop() }()

	correlationID := newCorrelationID()
	dlog.L().Info("aitelier.agent.start", "correlation_id", correlationID, "agent", a.agent, "model", a.model)

	req := chatCompletionRequest{
		Model:          a.modelString(),
		Messages:       toChatMessages(messages),
		ResponseFormat: a.responseSchema,
		Aitelier: &aitelierOpts{
			MCPServers: []mcpServerSpec{
				{Name: mcpServerName, Transport: "http", URL: mcp.URL()},
			},
			ToolAllowlist: buildAllowlist(tools),
			MaxTurns:      10,
			TraceTag:      correlationID,
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal chat request: %w", err)
	}

	preActive := a.listActiveRuns(ctx)

	type result struct {
		resp *chatCompletionResponse
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		httpReq, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/v1/chat/completions", bytes.NewReader(body))
		if err != nil {
			resCh <- result{err: fmt.Errorf("build chat request: %w", err)}
			return
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("X-Correlation-Id", correlationID)
		if a.apiKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
		}

		httpResp, err := a.client.Do(httpReq)
		if err != nil {
			resCh <- result{err: fmt.Errorf("aitelier /v1/chat/completions: %w", err)}
			return
		}
		defer httpResp.Body.Close()

		raw, err := io.ReadAll(httpResp.Body)
		if err != nil {
			resCh <- result{err: fmt.Errorf("read chat response: %w", err)}
			return
		}

		if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
			var eb chatCompletionErrorBody
			if err := json.Unmarshal(raw, &eb); err == nil && eb.Error.Type != "" {
				if eb.Error.Type == "Cancelled" {
					resCh <- result{err: fmt.Errorf("%w: %s", ErrAtelierCancelled, eb.Error.Message)}
					return
				}
				resCh <- result{err: fmt.Errorf("aitelier error (%s): %s", eb.Error.Type, eb.Error.Message)}
				return
			}
			resCh <- result{err: fmt.Errorf("aitelier HTTP %d: %s", httpResp.StatusCode, strings.TrimSpace(string(raw)))}
			return
		}

		var r chatCompletionResponse
		if err := json.Unmarshal(raw, &r); err != nil {
			return
		}
		resCh <- result{resp: &r}
	}()

	select {
	case <-ctx.Done():
		a.cancelNewRuns(preActive)
		<-resCh
		return nil, ctx.Err()
	case r := <-resCh:
		if r.err != nil {
			return nil, r.err
		}
		resp := r.resp
		if len(resp.Choices) == 0 {
			return nil, fmt.Errorf("aitelier returned no choices")
		}
		ch := resp.Choices[0]

		content := ch.Message.Content
		// Prefer server-side parsed JSON when aitelier surfaced it.
		if ch.Message.AitelierParsed != nil {
			if parsed, err := json.Marshal(ch.Message.AitelierParsed); err == nil {
				content = string(parsed)
			}
		}

		toolNames := a.fetchToolNames(resp.AitelierRunID)

		return &Message{
			Role:      "assistant",
			Content:   content,
			ToolsUsed: toolNames,
		}, nil
	}
}

// fetchToolNames pulls the run's event timeline and extracts tool names from
// tool_call events. Used because OpenAI's ChatCompletion shape doesn't include
// inner-agent tool calls. Best-effort — returns nil on any failure.
func (a *AtelierBackend) fetchToolNames(runID string) []string {
	if runID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", a.baseURL+"/v1/runs/"+runID+"/events", nil)
	if err != nil {
		return nil
	}
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var events []runEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil
	}
	var names []string
	for _, e := range events {
		if e.Kind != "tool_call" {
			continue
		}
		if name, ok := e.Payload["tool"].(string); ok && name != "" {
			names = append(names, name)
		}
	}
	return names
}

// CheckAvailable hits /v1/discovery and confirms the sandbox agent is reachable.
func (a *AtelierBackend) CheckAvailable(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", a.baseURL+"/v1/discovery", nil)
	if err != nil {
		return err
	}
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("aitelier not reachable at %s: %w", a.baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return a.checkHealthFallback(ctx)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("aitelier /v1/discovery returned %d", resp.StatusCode)
	}
	var d discoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return fmt.Errorf("decode /v1/discovery: %w", err)
	}
	if !d.Dependencies.SandboxAgent.Reachable {
		return fmt.Errorf("aitelier reports sandbox agent unreachable — agent runs cannot proceed")
	}
	return nil
}

func (a *AtelierBackend) checkHealthFallback(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", a.baseURL+"/v1/health", nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("aitelier not reachable at %s: %w", a.baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("aitelier /v1/health returned %d", resp.StatusCode)
	}
	return nil
}

func (a *AtelierBackend) listActiveRuns(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	req, err := http.NewRequestWithContext(ctx, "GET", a.baseURL+"/v1/runs/active", nil)
	if err != nil {
		return out
	}
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	var ar activeRunsResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return out
	}
	for _, id := range ar.Active {
		out[id] = true
	}
	return out
}

func (a *AtelierBackend) cancelNewRuns(before map[string]bool) {
	bg, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	after := a.listActiveRuns(bg)
	var wg sync.WaitGroup
	for id := range after {
		if before[id] {
			continue
		}
		wg.Add(1)
		go func(runID string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(bg, "POST", a.baseURL+"/v1/runs/"+runID+"/cancel", nil)
			if err != nil {
				return
			}
			if a.apiKey != "" {
				req.Header.Set("Authorization", "Bearer "+a.apiKey)
			}
			resp, err := a.client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			dlog.L().Info("aitelier.cancel", "run_id", runID)
		}(id)
	}
	wg.Wait()
}

// toChatMessages converts the planner's Message list into OpenAI chat messages.
// Drops tool_result-role messages which OpenAI's API doesn't accept without an
// accompanying tool_call_id — the agent path doesn't use those anyway.
func toChatMessages(messages []Message) []chatMessage {
	out := make([]chatMessage, 0, len(messages))
	for _, m := range messages {
		switch m.Role {
		case "system", "user", "assistant":
			out = append(out, chatMessage{Role: m.Role, Content: m.Content})
		}
	}
	return out
}

func buildAllowlist(tools []Tool) []string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = mcpToolName(t.Name)
	}
	return out
}

// newCorrelationID returns a dispatcher-prefixed correlation id. Used as both
// the X-Correlation-Id header and the trace_tag on the request, so
// `aitelier traces --tag dispatcher-<id>` retrieves the matching trace.
func newCorrelationID() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "dispatcher-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000"), ".", "")
	}
	return "dispatcher-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}

// planResultResponseFormat mirrors dispatcher's Go types (internal/types/plan.go)
// so the agent's structured output decodes directly into PlanResult.
func planResultResponseFormat() *responseFormat {
	confidenceValues := []string{
		string(types.ConfidenceHigh),
		string(types.ConfidenceMedium),
		string(types.ConfidenceLow),
		string(types.ConfidenceUnknown),
	}
	costEstimate := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"value":       map[string]any{"type": "number"},
			"currency":    map[string]any{"type": "string"},
			"confidence":  map[string]any{"type": "string", "enum": confidenceValues},
			"assumptions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"exclusions":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
	}
	stringArray := map[string]any{"type": "array", "items": map[string]any{"type": "string"}}

	return &responseFormat{
		Type: "json_schema",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"explanation": map[string]any{"type": "string"},
				"recommendation": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"target":        map[string]any{"type": "string"},
						"runtime":       map[string]any{"type": "string"},
						"estimatedCost": costEstimate,
						"reason":        stringArray,
					},
				},
				"alternatives": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"target":        map[string]any{"type": "string"},
							"runtime":       map[string]any{"type": "string"},
							"estimatedCost": costEstimate,
							"tradeoff":      stringArray,
						},
					},
				},
				"rejected": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"target": map[string]any{"type": "string"},
							"reason": map[string]any{"type": "string"},
						},
					},
				},
				"risks": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"category":    map[string]any{"type": "string"},
							"description": map[string]any{"type": "string"},
						},
					},
				},
				"approvals": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"name":   map[string]any{"type": "string"},
							"reason": map[string]any{"type": "string"},
						},
					},
				},
				"suggestions": stringArray,
				"toolsUsed":   stringArray,
			},
			"required": []string{"explanation"},
		},
	}
}

// auditResultResponseFormat mirrors planner.AuditResult. The strict schema
// pins down field names and severity enums so the inner agent can't return a
// near-miss shape (e.g. "warn" instead of "warning", "message" instead of
// "title+detail") that our parser would treat as the wrong schema.
func auditResultResponseFormat() *responseFormat {
	severities := []string{"critical", "warning", "info"}
	categories := []string{"secrets", "cost", "reliability", "compliance", "config"}
	verdicts := []string{"ready", "concerns", "blocked"}
	finding := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"severity":   map[string]any{"type": "string", "enum": severities},
			"category":   map[string]any{"type": "string", "enum": categories},
			"title":      map[string]any{"type": "string"},
			"detail":     map[string]any{"type": "string"},
			"suggestion": map[string]any{"type": "string"},
		},
		"required": []string{"severity", "category", "title"},
	}
	return &responseFormat{
		Type: "json_schema",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"summary":   map[string]any{"type": "string"},
				"verdict":   map[string]any{"type": "string", "enum": verdicts},
				"findings":  map[string]any{"type": "array", "items": finding},
				"toolsUsed": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []string{"summary", "verdict", "findings"},
		},
	}
}

// diagnoseResultResponseFormat mirrors planner.DiagnoseResult.
func diagnoseResultResponseFormat() *responseFormat {
	severities := []string{"info", "warning", "error"}
	return &responseFormat{
		Type: "json_schema",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"explanation":    map[string]any{"type": "string"},
				"likelyCause":    map[string]any{"type": "string"},
				"severity":       map[string]any{"type": "string", "enum": severities},
				"recommendation": map[string]any{"type": "string"},
				"nextSteps":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"toolsUsed":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []string{"explanation"},
		},
	}
}
