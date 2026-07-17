package cloudvm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSetupWatchdogIntervalRenewsWellBeforeTTL(t *testing.T) {
	// A large TTL renews at ttl/3 (two renewals of headroom before the deadline).
	assert.Equal(t, 20*time.Minute/3, setupWatchdogInterval(20*time.Minute))
	// The floor: a sub-3s TTL clamps to 1s so renewals don't hot-loop.
	assert.Equal(t, time.Second, setupWatchdogInterval(3*time.Second), "sub-3s TTL hits the 1s floor")
	assert.Equal(t, time.Second, setupWatchdogInterval(100*time.Millisecond), "even a tiny TTL never renews faster than 1s")
}

// maintainSetupWatchdog with an already-cancelled context must return a working
// stop func and unwind promptly (not block on renewals against the unreachable
// test IP).
func TestMaintainSetupWatchdogStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		stop := maintainSetupWatchdog(ctx, &CloudVMState{IP: "192.0.2.1"}, 20*time.Minute)
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("maintainSetupWatchdog did not unwind on a cancelled context")
	}
}
