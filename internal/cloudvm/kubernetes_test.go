package cloudvm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The Job must carry an absolute lifetime ceiling (activeDeadlineSeconds, from
// MaxDuration) AND an in-pod renewable watchdog replacing the fixed 24h sleep,
// so an orphaned Job self-terminates at the watchdog TTL instead of running 24h.
func TestBuildJobManifest_HasDeadlineAndWatchdog(t *testing.T) {
	k := NewKubernetesProvider("default")
	opts := VMOptions{
		Name:               "dispatcher-job",
		Image:              "ubuntu:24.04",
		WatchdogTTLSeconds: 1800,
		MaxLifetimeSeconds: 3600,
		Tags:               map[string]string{"dispatcher-run-id": "run_1"},
	}

	m := k.buildJobManifest(opts.Name, opts.Image, opts)

	assert.Contains(t, m, "activeDeadlineSeconds: 3600", "absolute ceiling from MaxDuration")
	assert.NotContains(t, m, "sleep 86400", "fixed 24h keep-alive replaced by the watchdog")
	assert.Contains(t, m, "/tmp/dispatcher/watchdog", "in-pod renewable watchdog deadline file")
	assert.Contains(t, m, "1800", "initial watchdog deadline uses the configured TTL")
}

func TestBuildJobManifest_NoDeadlineWhenMaxLifetimeUnset(t *testing.T) {
	k := NewKubernetesProvider("default")
	opts := VMOptions{Name: "j", Image: "ubuntu", WatchdogTTLSeconds: 1800}

	m := k.buildJobManifest(opts.Name, opts.Image, opts)

	assert.NotContains(t, m, "activeDeadlineSeconds", "no absolute ceiling when MaxDuration is unset")
}

func TestK8sWatchdogScript_SelfDestructsAndIsRenewable(t *testing.T) {
	s := k8sWatchdogScript(1800)

	assert.Contains(t, s, "1800", "initial deadline derived from the TTL")
	assert.Contains(t, s, "exit 0", "self-terminates when the deadline passes")
	assert.Contains(t, s, "/tmp/dispatcher/watchdog", "reads the renewable deadline file")
}

func TestK8sRenewCommand_WritesDeadline(t *testing.T) {
	c := k8sRenewCommand(900)

	assert.Contains(t, c, "900")
	assert.Contains(t, c, "> /tmp/dispatcher/watchdog")
}
