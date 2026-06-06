package adapter

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/d0cd/dispatcher/internal/workload"
)

// SanitizeName lowercases, replaces /._<space> with `-`, and caps at 40 chars.
func SanitizeName(name string) string {
	r := strings.NewReplacer("/", "-", ".", "-", " ", "-", "_", "-")
	s := strings.ToLower(r.Replace(name))
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// RuntimeCommand returns the argv to invoke entrypoint under rt. forContainer
// switches python3 → python (containers ship `python` as the executable).
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

// WriteDotEnvFile writes the workload's .env values to a 0600 temp file
// and returns the path plus a cleanup func. Empty .env returns ("", noop, nil).
// Values stay off argv (where `ps` could see them); the file is the standard
// way to feed env into docker --env-file or similar.
func WriteDotEnvFile(dir string) (path string, cleanup func(), err error) {
	noop := func() {}
	kv, err := workload.LoadDotEnv(dir)
	if err != nil {
		return "", noop, err
	}
	if len(kv) == 0 {
		return "", noop, nil
	}
	var buf strings.Builder
	for k, v := range kv {
		fmt.Fprintf(&buf, "%s=%s\n", k, v)
	}
	name, err := WriteSecureTempFile("dispatcher-env-*.env", []byte(buf.String()))
	if err != nil {
		return "", noop, fmt.Errorf("write env file: %w", err)
	}
	return name, func() { _ = os.Remove(name) }, nil
}

// WriteSecureTempFile creates a tempfile mode 0600 atomically: O_CREATE|
// O_EXCL|O_WRONLY with explicit perm bits, no create-then-chmod TOCTOU.
// pattern follows os.CreateTemp's "*" convention. Caller owns Remove.
func WriteSecureTempFile(pattern string, contents []byte) (string, error) {
	for attempt := 0; attempt < 10; attempt++ {
		name, err := expandTempPattern(pattern)
		if err != nil {
			return "", err
		}
		path := filepath.Join(os.TempDir(), name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", err
		}
		if _, err := f.Write(contents); err != nil {
			f.Close()
			_ = os.Remove(path)
			return "", err
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(path)
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("could not allocate unique tempfile after 10 attempts")
}

func expandTempPattern(p string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("entropy unavailable: %w", err)
	}
	rnd := hex.EncodeToString(b[:])
	if strings.Contains(p, "*") {
		return strings.Replace(p, "*", rnd, 1), nil
	}
	return p + rnd, nil
}

// DotEnvShellPrefix returns "K1=V1 K2=V2 " for inline shell env injection.
// Values leak to `ps`; prefer DotEnvExportScript whenever stdin works.
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

// DotEnvExportScript renders .env as `export K='V'` lines for stdin-piped
// bash; values stay off argv. Empty string when no .env.
func DotEnvExportScript(dir string) (string, error) {
	kv, err := workload.LoadDotEnv(dir)
	if err != nil {
		return "", err
	}
	if len(kv) == 0 {
		return "", nil
	}
	var b strings.Builder
	for k, v := range kv {
		b.WriteString("export ")
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(ShellQuote(v))
		b.WriteByte('\n')
	}
	return b.String(), nil
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
