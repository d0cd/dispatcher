package adapter

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

// staleEnvFileThreshold is how old a dispatcher-env tempfile must be before
// SweepStaleEnvFiles will remove it. Older-than-threshold avoids racing a
// sibling dispatcher process that just wrote one.
const staleEnvFileThreshold = time.Hour

// SweepStaleEnvFiles best-effort removes orphaned dispatcher-env tempfiles
// (plaintext secrets) left behind by a crash between Execute and Cleanup.
// Only files older than staleEnvFileThreshold are removed so a freshly
// written sibling file is never deleted out from under another process.
func SweepStaleEnvFiles() error {
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "dispatcher-env-*.env"))
	if err != nil {
		return nil
	}
	cutoff := time.Now().Add(-staleEnvFileThreshold)
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(m)
		}
	}
	return nil
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

// dotEnvHeredocTerminator is the heredoc token used to feed docker
// --env-file /dev/stdin over SSH. A value containing it (or a newline) would
// terminate the heredoc early and corrupt the env stream, so DotEnvFileLines
// rejects such values.
const dotEnvHeredocTerminator = "DISPATCHER_ENV_EOF"

// DotEnvFileLines renders .env as sorted bare "K=V\n" lines suitable for
// docker's --env-file format (no `export`, no shell quoting; values are read
// literally). It returns an error if any value contains a newline or the
// heredoc terminator token, which would corrupt a `--env-file /dev/stdin`
// heredoc. Empty string when no .env.
func DotEnvFileLines(dir string) (string, error) {
	kv, err := workload.LoadDotEnv(dir)
	if err != nil {
		return "", err
	}
	if len(kv) == 0 {
		return "", nil
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := kv[k]
		if strings.ContainsRune(v, '\n') || strings.Contains(v, dotEnvHeredocTerminator) {
			return "", fmt.Errorf("env value for %q cannot contain a newline or %q", k, dotEnvHeredocTerminator)
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
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
