package adapter

import (
	"fmt"
	"strings"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/d0cd/dispatcher/internal/workload"
)

// SanitizeName normalizes a name for use in resource identifiers.
// Replaces special characters with hyphens, lowercases, and truncates.
func SanitizeName(name string) string {
	r := strings.NewReplacer("/", "-", ".", "-", " ", "-", "_", "-")
	s := strings.ToLower(r.Replace(name))
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// RuntimeCommand returns the command to run an entrypoint for a given runtime.
// Use forContainer=true for container environments (uses "python"),
// forContainer=false for local environments (prefers "python3").
func RuntimeCommand(rt types.Runtime, entrypoint string, forContainer bool) []string {
	switch rt {
	case types.RuntimePython:
		bin := "python3"
		if forContainer {
			bin = "python"
		}
		return []string{bin, entrypoint}
	case types.RuntimeNode:
		return []string{"node", entrypoint}
	case types.RuntimeGo:
		return []string{"go", "run", entrypoint}
	case types.RuntimeRuby:
		return []string{"ruby", entrypoint}
	case types.RuntimeRust:
		return []string{"cargo", "run"}
	case types.RuntimeJava:
		return []string{"java", entrypoint}
	default:
		return []string{entrypoint}
	}
}

// ShellQuote escapes a string for safe use in a shell command.
// Wraps the string in single quotes and escapes any embedded single quotes.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// ShellQuoteArgs quotes and joins multiple arguments for shell use.
func ShellQuoteArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = ShellQuote(a)
	}
	return strings.Join(quoted, " ")
}

// injectDotEnv reads .env (and .env.local) from dir and returns base extended
// with their KEY=VALUE pairs. Existing keys in base are overridden so workload
// .env wins over the inherited shell environment.
func injectDotEnv(base []string, dir string) ([]string, error) {
	kv, err := workload.LoadDotEnv(dir)
	if err != nil {
		return nil, fmt.Errorf("load .env from %s: %w", dir, err)
	}
	if len(kv) == 0 {
		return base, nil
	}
	out := make([]string, 0, len(base)+len(kv))
	override := map[string]bool{}
	for k := range kv {
		override[k] = true
	}
	for _, kvPair := range base {
		eq := strings.IndexByte(kvPair, '=')
		if eq > 0 && override[kvPair[:eq]] {
			continue
		}
		out = append(out, kvPair)
	}
	for k, v := range kv {
		out = append(out, k+"="+v)
	}
	return out, nil
}

// DotEnvArgs returns "-e KEY=VAL" pairs for any .env entries in dir, suitable
// for `docker run` / `docker exec` etc.
func DotEnvArgs(dir string) ([]string, error) {
	kv, err := workload.LoadDotEnv(dir)
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, 2*len(kv))
	for k, v := range kv {
		args = append(args, "-e", k+"="+v)
	}
	return args, nil
}

// DotEnvShellPrefix returns a "K1=V1 K2=V2 " string (note trailing space) so
// callers can prepend it to a shell command for inline env injection.
// Returns the empty string when no .env is present.
func DotEnvShellPrefix(dir string) (string, error) {
	kv, err := workload.LoadDotEnv(dir)
	if err != nil {
		return "", err
	}
	if len(kv) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(kv))
	for k, v := range kv {
		parts = append(parts, k+"="+ShellQuote(v))
	}
	return strings.Join(parts, " ") + " ", nil
}

// DefaultValidationResult returns a ValidationResult with sensible defaults.
func DefaultValidationResult() types.ValidationResult {
	return types.ValidationResult{
		Schema:             types.ValidationPass,
		PackageBuild:       types.ValidationPass,
		TargetCapabilities: types.ValidationPass,
		Credentials:        types.ValidationSkipped,
		Quota:              types.ValidationSkipped,
		Network:            types.ValidationPass,
		Policy:             types.ValidationPass,
		CostEstimate:       types.ValidationPass,
		CleanupPlan:        types.ValidationPass,
	}
}
