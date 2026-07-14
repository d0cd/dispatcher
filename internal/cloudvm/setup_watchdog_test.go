package cloudvm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSetupWatchdogIntervalRenewsWellBeforeTTL(t *testing.T) {
	for _, ttl := range []time.Duration{20 * time.Minute, 3 * time.Second} {
		interval := setupWatchdogInterval(ttl)
		assert.Less(t, interval, ttl)
	}
}

func TestMaintainSetupWatchdogStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stop := maintainSetupWatchdog(ctx, &CloudVMState{IP: "192.0.2.1"}, 20*time.Minute)
	stop()
}
