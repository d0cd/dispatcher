package cloudvm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRsyncUploadArgsRetainAndResumePartialTransfers(t *testing.T) {
	args, err := rsyncUploadArgs(&CloudVMState{SSHWrapper: "/tmp/ssh-wrapper"}, t.TempDir(), "root@host:/work/")
	require.NoError(t, err)

	assert.Contains(t, args, "--partial")
	assert.Contains(t, args, "--append-verify")
	assert.Equal(t, "root@host:/work/", args[len(args)-1])
}
