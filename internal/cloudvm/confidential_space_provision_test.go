package cloudvm

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGCPConfidentialSpaceCreateArgs(t *testing.T) {
	opts := VMOptions{
		Name:                   "dispatcher-cs-job",
		ConfidentialSpaceImage: "us-east1-docker.pkg.dev/p/r/attest@sha256:abc",
		Tags:                   map[string]string{"dispatcher": "true", "dispatcher-run-id": "run-1"},
	}
	args := gcpConfidentialSpaceCreateArgs(opts, "us-east4-a", "proj")
	joined := strings.Join(args, " ")

	// The single non-obvious, live-validated requirement: without cloud-platform
	// scope the launcher's verifier fails and the workload never runs.
	assert.True(t, slices.Contains(args, "--scopes=cloud-platform"), "must request cloud-platform scope")

	assert.True(t, slices.Contains(args, "--confidential-compute-type=SEV"))
	assert.True(t, slices.Contains(args, "--shielded-secure-boot"))
	assert.True(t, slices.Contains(args, "--maintenance-policy=TERMINATE"))
	assert.True(t, slices.Contains(args, "--image-family=confidential-space"))
	assert.True(t, slices.Contains(args, "--image-project=confidential-space-images"))

	assert.Contains(t, joined, "tee-image-reference=us-east1-docker.pkg.dev/p/r/attest@sha256:abc")
	assert.Contains(t, joined, "tee-container-log-redirect=true")
	assert.Contains(t, joined, "tee-restart-policy=Never")

	// The workload IS the container — no SSH surface on this path.
	assert.NotContains(t, joined, "ssh-keys")
	assert.NotContains(t, joined, "startup-script")

	// Pinned placement + machine + labels for GC.
	assert.True(t, slices.Contains(args, "us-east4-a"))
	assert.True(t, slices.Contains(args, "proj"))
	assert.True(t, slices.Contains(args, "n2d-standard-2"), "defaults to an SEV-capable machine")
	assert.Contains(t, joined, "dispatcher-run-id=run-1", "labelled so gc can reap it")
}

func TestGCPConfidentialSpaceCreateArgs_HonorsExplicitMachine(t *testing.T) {
	args := gcpConfidentialSpaceCreateArgs(VMOptions{
		Name: "x", InstanceType: "n2d-standard-8", ConfidentialSpaceImage: "ref@sha256:d",
	}, "z", "")
	assert.True(t, slices.Contains(args, "n2d-standard-8"))
	assert.False(t, slices.Contains(args, "--project"), "no project flag when project is empty")
}

func TestGCPConfidentialSpaceCreateArgs_NetworkTagWhenFirewalled(t *testing.T) {
	opts := VMOptions{Name: "job", ConfidentialSpaceImage: "ref@sha256:d", ConfidentialAllowFrom: "203.0.113.4/32"}
	joined := strings.Join(gcpConfidentialSpaceCreateArgs(opts, "z", ""), " ")
	assert.Contains(t, joined, "--tags="+agentFirewallName("job"), "VM must carry the firewall's target tag")

	// Without a source CIDR there is no firewall, so no network tag.
	joinedNoFw := strings.Join(gcpConfidentialSpaceCreateArgs(VMOptions{Name: "job", ConfidentialSpaceImage: "r@sha256:d"}, "z", ""), " ")
	assert.NotContains(t, joinedNoFw, "--tags=")
}

func TestGCPAgentFirewallArgs(t *testing.T) {
	create := gcpAgentFirewallCreateArgs("dispatcher-cs-fw-job", "dispatcher-cs-fw-job", "203.0.113.4/32", "proj")
	joined := strings.Join(create, " ")
	assert.Contains(t, joined, "firewall-rules create dispatcher-cs-fw-job")
	assert.True(t, slices.Contains(create, "--allow=tcp:8443"), "opens exactly the agent port")
	assert.True(t, slices.Contains(create, "--source-ranges=203.0.113.4/32"), "scoped to dispatcher's egress IP")
	assert.True(t, slices.Contains(create, "--target-tags=dispatcher-cs-fw-job"))
	assert.True(t, slices.Contains(create, "--project"))

	del := gcpAgentFirewallDeleteArgs("dispatcher-cs-fw-job", "")
	assert.Contains(t, strings.Join(del, " "), "firewall-rules delete dispatcher-cs-fw-job")
	assert.False(t, slices.Contains(del, "--project"), "no project flag when empty")
}
