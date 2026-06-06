package planner

import "strings"

const (
	mcpServerName = "dispatcher"
	mcpToolPrefix = "mcp__" + mcpServerName + "__"
)

func mcpToolName(tool string) string { return mcpToolPrefix + tool }

// StripMCPPrefix is the inverse of mcpToolName — reports a dispatch-native tool
// name regardless of whether the agent reported it with the MCP namespace.
func StripMCPPrefix(name string) string { return strings.TrimPrefix(name, mcpToolPrefix) }
