package cloudvm

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The GCP per-run SSH firewall must restrict tcp:22 to the CIDR with a DENY+ALLOW
// pair (a pure ALLOW can't subtract the default-allow-ssh). Verify the argv.
func TestGCPSSHFirewallArgs(t *testing.T) {
	allow, deny := gcpSSHFirewallArgs("dispatcher-fw-run1", "203.0.113.4/32", "run1", "proj")
	aj := strings.Join(allow, " ")
	dj := strings.Join(deny, " ")

	// ALLOW: from the CIDR, higher precedence (lower priority number).
	assert.Contains(t, aj, "firewall-rules create dispatcher-fw-run1 ")
	assert.Contains(t, aj, "--action=ALLOW")
	assert.Contains(t, aj, "--rules=tcp:22")
	assert.Contains(t, aj, "--source-ranges=203.0.113.4/32")
	assert.Contains(t, aj, "--target-tags=dispatcher-fw-run1")
	assert.Contains(t, aj, "--priority=900")
	assert.Contains(t, aj, "dispatcher-run-id=run1")

	// DENY: everyone else, lower precedence than ALLOW but above default-allow-ssh.
	assert.Contains(t, dj, "firewall-rules create dispatcher-fw-run1-deny ")
	assert.Contains(t, dj, "--action=DENY")
	assert.Contains(t, dj, "--source-ranges=0.0.0.0/0")
	assert.Contains(t, dj, "--target-tags=dispatcher-fw-run1")
	assert.Contains(t, dj, "--priority=1000")

	// No project → no --project flag.
	allowNP, _ := gcpSSHFirewallArgs("dispatcher-fw-x", "10.0.0.0/8", "x", "")
	assert.NotContains(t, strings.Join(allowNP, " "), "--project")
}

// CreateVM with --allow-ssh-from must create the firewall and tag the instance;
// without it, no firewall calls and no tag.
func TestGCPCreateVM_SSHFirewallLifecycle(t *testing.T) {
	prevRun, prevRetry := runCLI, retryCLIOutput
	t.Cleanup(func() { runCLI = prevRun; retryCLIOutput = prevRetry })
	var calls []string
	runCLI = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte(`{}`), nil
	}
	retryCLIOutput = func(_ context.Context, _, _ string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte(`[{"name":"vm1","networkInterfaces":[{"accessConfigs":[{"natIP":"1.2.3.4"}]}]}]`), nil
	}
	g := NewGCPProvider("proj", "us-central1-a")
	_, err := g.CreateVM(context.Background(), VMOptions{
		Name: "vm1", InstanceType: "e2-small", AllowSSHFrom: "203.0.113.4/32",
		Tags: map[string]string{"dispatcher-run-id": "run1"},
	})
	require.NoError(t, err)
	joined := strings.Join(calls, "\n")
	assert.Contains(t, joined, "firewall-rules create dispatcher-fw-run1-deny", "must create the deny rule")
	assert.Contains(t, joined, "firewall-rules create dispatcher-fw-run1 ", "must create the allow rule")
	assert.Contains(t, joined, "--tags=dispatcher-fw-run1", "the instance must carry the firewall tag")
}
