//go:build sshe2e

// SSH e2e tests exercise the real SSHAdapter against a live host. They're
// excluded from the normal suite (build tag sshe2e) because they need
// passwordless SSH. Run them against localhost with, e.g.:
//
//	# ensure `ssh localhost true` works without a prompt (key auth), then:
//	go test -tags sshe2e -run TestSSHE2E ./internal/adapter/
//
// They validate the part that can't be unit-tested: that artifact retrieval
// actually rsyncs a workload's outputs/ directory back over a real SSH
// connection — the scp-back path that replaced the old silent (nil, nil) no-op.
package adapter

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireSSHLocalhost skips unless passwordless SSH to localhost works. It
// leaves HOME untouched so ssh finds the real keys/known_hosts.
func requireSSHLocalhost(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("ssh",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=5",
		"localhost", "true")
	if err := cmd.Run(); err != nil {
		t.Skipf("no passwordless ssh to localhost: %v", err)
	}
	user := os.Getenv("USER")
	if user == "" {
		t.Skip("USER not set")
	}
	return user
}

// A workload's declared outputs/ directory must come back from the remote host
// into the run's local artifacts tree — over a real rsync-over-ssh, with the
// security flags applied by the production code path.
func TestSSHE2E_RetrievesOutputsDir(t *testing.T) {
	user := requireSSHLocalhost(t)
	// Redirect the state dir (where artifacts land) without touching HOME, so
	// ssh still resolves the real ~/.ssh keys.
	t.Setenv("DISPATCHER_HOME", t.TempDir())

	// The "remote" working dir (same machine over loopback). Drop the two
	// artifacts produces-outputs would write.
	remote := t.TempDir()
	outDir := filepath.Join(remote, "outputs")
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "result.json"), []byte(`{"status":"ok","sum":15}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "run.log"), []byte("done\n"), 0o644))

	a := NewSSHAdapter(SSHConfig{Host: "localhost", User: user, RemoteDir: remote})
	h := &RunHandle{ID: "ssh-e2e", RunID: "run-e2e", State: &sshState{outputs: []string{"outputs"}}}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	refs, err := a.Artifacts(ctx, h)
	require.NoError(t, err)
	require.NotEmpty(t, refs, "outputs/ must be retrieved")

	byName := map[string]string{}
	for _, r := range refs {
		byName[r.Name] = r.Path
	}
	require.Contains(t, byName, "result.json")
	require.Contains(t, byName, "run.log")

	data, err := os.ReadFile(byName["result.json"])
	require.NoError(t, err)
	assert.Contains(t, string(data), `"sum":15`, "retrieved file content must match what the workload wrote")
}
