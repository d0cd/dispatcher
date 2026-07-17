package adapter

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubRunRsync replaces the runRsync seam so artifact retrieval can be exercised
// without a live SSH host, capturing the exact rsync argv.
func stubRunRsync(t *testing.T, fn func(ctx context.Context, args ...string) error) {
	t.Helper()
	prev := runRsync
	runRsync = fn
	t.Cleanup(func() { runRsync = prev })
}

func TestSSHAdapter_Artifacts_RsyncsEachOutputSecurely(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var calls [][]string
	stubRunRsync(t, func(_ context.Context, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		dest := args[len(args)-1] // local dest is the final rsync arg
		if err := os.MkdirAll(dest, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dest, "out.txt"), []byte("x"), 0o600)
	})

	a := NewSSHAdapter(SSHConfig{Host: "host.example", User: "ubuntu", KeyFile: "/k", RemoteDir: "/tmp/dispatcher"})
	h := &RunHandle{ID: "ssh-x", RunID: "run-1", State: &sshState{outputs: []string{"results"}}}

	refs, err := a.Artifacts(context.Background(), h)
	require.NoError(t, err)
	require.Len(t, calls, 1, "one rsync per output path")

	got := calls[0]
	assert.True(t, containsAdjacent(got, []string{"--safe-links", "--protect-args"}),
		"must harden rsync against symlink escape and remote re-tokenization")
	assert.Contains(t, got, "ubuntu@host.example:/tmp/dispatcher/results",
		"remote source must be user@host:<remoteDir>/<output>")
	require.NotEmpty(t, refs)
	assert.Equal(t, "out.txt", refs[0].Name)
}

func TestSSHAdapter_Artifacts_RsyncErrorSurfaces(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stubRunRsync(t, func(_ context.Context, _ ...string) error { return assert.AnError })
	a := NewSSHAdapter(SSHConfig{Host: "h", User: "u", RemoteDir: "/tmp/dispatcher"})
	h := &RunHandle{ID: "x", RunID: "r", State: &sshState{outputs: []string{"results"}}}
	refs, err := a.Artifacts(context.Background(), h)
	assert.Error(t, err, "a failed transfer must surface, not be swallowed")
	assert.Empty(t, refs)
}

func TestSSHAdapter_Artifacts_NoOutputsIsNoop(t *testing.T) {
	called := false
	stubRunRsync(t, func(_ context.Context, _ ...string) error { called = true; return nil })
	a := NewSSHAdapter(SSHConfig{Host: "h", User: "u"})
	refs, err := a.Artifacts(context.Background(), &RunHandle{State: &sshState{outputs: nil}})
	require.NoError(t, err)
	assert.Nil(t, refs)
	assert.False(t, called, "no outputs → no rsync")
}

func TestSSHAdapter_Artifacts_RejectsUnsafeOutput(t *testing.T) {
	for _, out := range []string{"../escape", "/etc/passwd"} {
		t.Run(out, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			called := false
			stubRunRsync(t, func(_ context.Context, _ ...string) error { called = true; return nil })
			a := NewSSHAdapter(SSHConfig{Host: "h", User: "u", RemoteDir: "/tmp/dispatcher"})
			h := &RunHandle{ID: "x", RunID: "r", State: &sshState{outputs: []string{out}}}
			refs, err := a.Artifacts(context.Background(), h)
			assert.Error(t, err, "absolute/traversal output must be rejected")
			assert.Empty(t, refs)
			assert.False(t, called, "must not rsync an unsafe path")
		})
	}
}

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

func TestValidateRemoteDir_RejectsShellMetacharacters(t *testing.T) {
	// Cleanup passes RemoteDir into `ssh ... rm -rf -- <dir>`, which the remote
	// shell re-tokenizes. A metacharacter like ';' would start a second command
	// (`rm -rf -- /a/b; rm -rf /`) despite the `--`, so validation must reject it.
	for _, dir := range []string{
		"/a/b; rm -rf /",
		"/a/$(reboot)",
		"/a/`id`/b",
		"/a/b && wipe",
		"/a/b|tee",
		"/a b/c d", // whitespace
		"/a/b\nrm",
	} {
		if err := validateRemoteDir(dir); err == nil {
			t.Errorf("validateRemoteDir(%q) = nil, want rejection", dir)
		}
	}
	// A normal absolute path with two components still passes.
	if err := validateRemoteDir("/home/user/dispatcher"); err != nil {
		t.Errorf("validateRemoteDir(valid path) = %v, want nil", err)
	}
}

func TestSSHAdapter_LogsStreamsSubprocessOutput(t *testing.T) {
	// The ssh subprocess's stdout/stderr must reach the run's logWriter via Logs;
	// otherwise remote workload output is silently discarded to /dev/null.
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	cmd := exec.Command("printf", "hello-remote")
	cmd.Stdout = pw
	require.NoError(t, cmd.Start())
	pw.Close()

	a := NewSSHAdapter(SSHConfig{Host: "h", User: "u", Port: 22})
	h := &RunHandle{State: &sshState{cmd: cmd, logs: pr}}
	var buf bytes.Buffer
	require.NoError(t, a.Logs(context.Background(), h, &buf))
	assert.Equal(t, "hello-remote", buf.String())
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
