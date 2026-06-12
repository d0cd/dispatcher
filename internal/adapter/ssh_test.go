package adapter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// containsAdjacent reports whether want appears as a contiguous subsequence
// of got.
func containsAdjacent(got, want []string) bool {
	for i := 0; i+len(want) <= len(got); i++ {
		match := true
		for j := range want {
			if got[i+j] != want[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestSSHArgs_SetsStrictHostKeyChecking(t *testing.T) {
	a := NewSSHAdapter(SSHConfig{Host: "h", User: "u", Port: 2222, KeyFile: "/k"})
	args := a.sshArgs("echo", "ok")
	assert.True(t, containsAdjacent(args, []string{"-o", "StrictHostKeyChecking=accept-new"}),
		"sshArgs must set StrictHostKeyChecking=accept-new; got %v", args)
}

func TestRsyncSSHCmd_SetsStrictHostKeyChecking(t *testing.T) {
	withKey := rsyncSSHCmd(SSHConfig{Host: "h", User: "u", Port: 2222, KeyFile: "/k"})
	assert.Contains(t, withKey, "StrictHostKeyChecking=accept-new")

	noKey := rsyncSSHCmd(SSHConfig{Host: "h", User: "u", Port: 2222})
	assert.Contains(t, noKey, "StrictHostKeyChecking=accept-new")
}

// TestSSHDockerRunScript_QuotedHeredoc guards against remote command injection
// via .env: the heredoc delimiter must be single-quoted so the remote shell
// does not expand a value like FOO=$(cmd) before docker reads it.
func TestSSHDockerRunScript_QuotedHeredoc(t *testing.T) {
	script := sshDockerRunScript("'/tmp/dispatcher'", "'img:latest'", "FOO=$(id)\n")
	assert.Contains(t, script, "<<'DISPATCHER_ENV_EOF'",
		"heredoc delimiter must be single-quoted to prevent remote expansion")
	assert.NotContains(t, script, "<<DISPATCHER_ENV_EOF",
		"an unquoted heredoc delimiter would let the remote shell expand the env body")
	// The value is passed through literally, not expanded away.
	assert.Contains(t, script, "FOO=$(id)")
}

func TestDotEnvFileLines_PreservesRawValue(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"),
		[]byte(`TRICKY=a'\''b`+"\n"), 0o644))

	lines, err := DotEnvFileLines(dir)
	require.NoError(t, err)
	// Value must be the raw bytes LoadDotEnv produced, byte-for-byte.
	assert.Equal(t, `TRICKY=a'\''b`+"\n", lines)
}

func TestDotEnvFileLines_RejectsNewlineAndTerminator(t *testing.T) {
	// LoadDotEnv scans line-by-line, so a newline can't survive a real .env;
	// drive the validation directly by exercising the helper with values that
	// would corrupt the heredoc.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("BAD=hasDISPATCHER_ENV_EOFtoken\n"), 0o644))
	_, err := DotEnvFileLines(dir)
	require.Error(t, err, "value containing the heredoc terminator token must be rejected")
}
