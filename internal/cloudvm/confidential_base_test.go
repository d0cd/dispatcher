package cloudvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// detectEgressCIDR normally probes ipify for a /32, but a caller behind CGNAT / a
// NAT pool / an egress proxy sees a different source IP than the agent-port
// firewall would be scoped to, so it must honor an explicit override. A bad value
// fails closed rather than reaching the firewall argv.
func TestDetectEgressCIDR_Override(t *testing.T) {
	t.Setenv("DISPATCHER_AGENT_ALLOW_CIDR", "203.0.113.0/24")
	got, err := detectEgressCIDR(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.0/24", got, "explicit override is used without a network probe")

	t.Setenv("DISPATCHER_AGENT_ALLOW_CIDR", "not-a-cidr")
	_, err = detectEgressCIDR(context.Background())
	require.Error(t, err, "a non-CIDR override must fail closed")
}
