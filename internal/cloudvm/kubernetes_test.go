package cloudvm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// The rendered manifest must be structurally valid: the pod template's labels
// must land under template.metadata.labels, not leak in as stray top-level keys
// from a reused (under-indented) label block — which a Contains test can't catch
// and a strict cluster would reject.
func TestBuildJobManifest_PodTemplateLabelsWellFormed(t *testing.T) {
	k := NewKubernetesProvider("default")
	opts := VMOptions{
		Name: "j", Image: "ubuntu", WatchdogTTLSeconds: 1800,
		Tags: map[string]string{"dispatcher-run-id": "run_1"},
	}

	var doc map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(k.buildJobManifest(opts.Name, opts.Image, opts)), &doc))

	spec, _ := doc["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	require.NotNil(t, tmpl)
	assert.ElementsMatch(t, []string{"metadata", "spec"}, keysOf(tmpl),
		"pod template must have only metadata+spec (no misindented label keys leaking in)")

	meta, _ := tmpl["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	assert.Equal(t, "true", labels["dispatcher"], "pod template must carry its labels")
	assert.Equal(t, "run_1", labels["dispatcher-run-id"])
}

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
