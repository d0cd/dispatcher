package cloudvm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitForSSHAuth_RetriesUntilAuthenticated(t *testing.T) {
	prevProbe, prevInterval := sshProbe, sshAuthPollInterval
	t.Cleanup(func() { sshProbe = prevProbe; sshAuthPollInterval = prevInterval })
	sshAuthPollInterval = time.Millisecond

	var calls int
	sshProbe = func(context.Context, *CloudVMState) error {
		calls++
		if calls < 3 {
			return errors.New("Permission denied (publickey)")
		}
		return nil
	}
	err := WaitForSSHAuth(context.Background(), &CloudVMState{IP: "1.2.3.4"}, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, 3, calls, "retries until the key is accepted, not just TCP-ready")
}

func TestWaitForSSHAuth_TimesOut(t *testing.T) {
	prevProbe, prevInterval := sshProbe, sshAuthPollInterval
	t.Cleanup(func() { sshProbe = prevProbe; sshAuthPollInterval = prevInterval })
	sshAuthPollInterval = time.Millisecond

	sshProbe = func(context.Context, *CloudVMState) error { return errors.New("publickey") }
	err := WaitForSSHAuth(context.Background(), &CloudVMState{IP: "1.2.3.4"}, 30*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authenticated SSH")
	assert.Contains(t, err.Error(), "publickey", "timeout must retain the actionable SSH failure")
}
