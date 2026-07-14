package cloudvm

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSSHWrapper_UsesOnlyPerRunIdentity(t *testing.T) {
	t.Setenv("DISPATCHER_HOME", t.TempDir())
	path, err := writeSSHWrapper(&CloudVMState{
		IP: "192.0.2.1", SSHKeyPath: "/keys/per-run", KnownHostsPath: "/keys/known-hosts",
	}, "run1")
	require.NoError(t, err)

	body, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(body), "-o ServerAliveInterval=15 -o ServerAliveCountMax=6")
	assert.Contains(t, string(body), "-o IdentitiesOnly=yes -i '/keys/per-run'")
}
