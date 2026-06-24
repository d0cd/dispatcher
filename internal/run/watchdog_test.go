package run

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/types"
)

func TestNewRun_CarriesConfiguredWatchdogTTL(t *testing.T) {
	p := testPlan()
	p.Constraints.WatchdogTTL = 2 * time.Hour

	r := NewRun(p)

	assert.Equal(t, 2*time.Hour, r.WatchdogTTL)
}

func runningRun(t *testing.T, ttl time.Duration) *Run {
	t.Helper()
	p := testPlan()
	p.Constraints.WatchdogTTL = ttl
	r := NewRun(p)
	r.mu.Lock()
	r.State = types.RunStateRunning
	r.mu.Unlock()
	r.Handle = &adapter.RunHandle{}
	return r
}

func TestRenewWatchdog_ExtendsByConfiguredTTL(t *testing.T) {
	r := runningRun(t, 2*time.Hour)
	m := &mockDurableAdapter{id: "test"}

	deadline, err := RenewWatchdog(context.Background(), m, r)

	require.NoError(t, err)
	assert.Equal(t, 2*time.Hour, m.lastTTL, "extends by the configured TTL")
	assert.WithinDuration(t, time.Now().Add(2*time.Hour), deadline, time.Minute)
	assert.False(t, r.LastHeartbeat.IsZero(), "records the heartbeat")
}

func TestRenewWatchdog_DefaultsWhenTTLUnset(t *testing.T) {
	r := runningRun(t, 0)
	m := &mockDurableAdapter{id: "test"}

	_, err := RenewWatchdog(context.Background(), m, r)

	require.NoError(t, err)
	assert.Equal(t, DefaultWatchdogTTL, m.lastTTL, "falls back to the default TTL")
}

func TestRenewWatchdog_RefusesTerminalRun(t *testing.T) {
	r := runningRun(t, time.Hour)
	r.mu.Lock()
	r.State = types.RunStateCompleted
	r.mu.Unlock()
	m := &mockDurableAdapter{id: "test"}

	_, err := RenewWatchdog(context.Background(), m, r)

	require.Error(t, err, "a finished run has no watchdog to renew")
}

func TestRenewWatchdog_RefusesNonDurableAdapter(t *testing.T) {
	r := runningRun(t, time.Hour)

	_, err := RenewWatchdog(context.Background(), &mockAdapter{}, r)

	require.Error(t, err, "non-durable targets have no watchdog")
}

// TestRenewWatchdog_Integration exercises the full path the `renew` command and
// the `status` auto-renew hook run: persist a running durable run, reconnect to
// it through ReconnectToRun, renew its watchdog, then persist and reload — proving
// the configured TTL survives the save/reconnect round-trip and the heartbeat is
// durable.
func TestRenewWatchdog_Integration(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	p := testPlan()
	p.Constraints.WatchdogTTL = 2 * time.Hour
	r := NewRun(p)
	require.NoError(t, r.Transition(types.RunStatePlanning))
	require.NoError(t, r.Transition(types.RunStateValidated))
	require.NoError(t, r.Transition(types.RunStatePreparing))
	require.NoError(t, r.Transition(types.RunStateRunning))
	r.HandleID = "vm-renew-test"
	r.HandleState = json.RawMessage(`{"vmId":"i-test","ip":"1.2.3.4"}`)
	_, err := r.Save()
	require.NoError(t, err)

	ctx := context.Background()
	m := &mockDurableAdapter{id: r.TargetID}
	loaded, a, err := ReconnectToRun(ctx, r.ID, func(string) (adapter.TargetAdapter, error) { return m, nil })
	require.NoError(t, err)
	require.NotNil(t, loaded.Handle, "reconnect rebuilt the handle")

	deadline, err := RenewWatchdog(ctx, a, loaded)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Hour, m.lastTTL, "configured TTL survives the persist+reconnect round-trip")
	assert.WithinDuration(t, time.Now().Add(2*time.Hour), deadline, time.Minute)

	// Persist the heartbeat (what `renew` / the status hook do) and verify it round-trips.
	_, err = loaded.Save()
	require.NoError(t, err)
	reloaded, err := LoadRecord(r.ID)
	require.NoError(t, err)
	assert.False(t, reloaded.LastHeartbeat.IsZero(), "heartbeat persisted across save/load")
	assert.Equal(t, 2*time.Hour, reloaded.WatchdogTTL, "configured TTL persisted")
}
