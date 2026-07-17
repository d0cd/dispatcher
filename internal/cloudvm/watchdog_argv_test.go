package cloudvm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSSHCmdArgs(t *testing.T) {
	t.Run("pinned known_hosts uses StrictHostKeyChecking=yes", func(t *testing.T) {
		args := sshCmdArgs(&CloudVMState{
			KnownHostsPath: "/k/known_hosts", IP: "1.2.3.4",
			SSHKeyPath: "/k/id", SSHPort: 2222, SSHUser: "ubuntu",
		}, "true")
		assert.Equal(t, []string{
			"-o", "StrictHostKeyChecking=yes",
			"-o", "UserKnownHostsFile=/k/known_hosts",
			"-o", "ConnectTimeout=10",
			"-o", "ServerAliveInterval=15",
			"-o", "ServerAliveCountMax=6",
			"-o", "IdentitiesOnly=yes",
			"-i", "/k/id",
			"-p", "2222",
			"ubuntu@1.2.3.4",
			"true",
		}, args)
	})

	t.Run("no known_hosts falls back to no-checking with defaults", func(t *testing.T) {
		args := sshCmdArgs(&CloudVMState{IP: "1.2.3.4"}, "echo hi")
		assert.Equal(t, []string{
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=10",
			"-o", "ServerAliveInterval=15",
			"-o", "ServerAliveCountMax=6",
			"-p", "22",
			"root@1.2.3.4",
			"echo hi",
		}, args)
	})
}
