package cloudvm

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
)

func TestGCPAgentFirewallCreateArgs_CarriesRunID(t *testing.T) {
	args := gcpAgentFirewallCreateArgs("fw", "tag", "1.2.3.4/32", "run-9", "p")
	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "--description=dispatcher-run-id=run-9",
		"the run id rides in the description so a leaked firewall is an orphan, not just standing")
}

func TestGCPListFirewallResources(t *testing.T) {
	fwJSON := `[
	  {"name":"dispatcher-fw-cs-job","description":"dispatcher-run-id=run-9"},
	  {"name":"default-allow-ssh","description":""}
	]`
	captureRunCLIWith(t, func(string, ...string) ([]byte, error) { return []byte(fwJSON), nil })

	g := &GCPProvider{project: "p"}
	res, err := g.listFirewallResources(context.Background())
	require.NoError(t, err)
	require.Len(t, res, 1, "only dispatcher-owned firewalls, never the project's own rules")
	assert.Equal(t, "dispatcher-fw-cs-job", res[0].ResourceID)
	assert.Equal(t, adapter.ResourceFirewall, res[0].Kind)
	assert.Equal(t, "run-9", res[0].RunID, "run id parsed from description → orphan-reapable")
	assert.True(t, res[0].DispatcherOwned())
}

func TestGCPDestroyFirewall(t *testing.T) {
	calls := captureRunCLI(t)
	g := &GCPProvider{project: "p"}
	_ = g.DestroyResource(context.Background(), adapter.ResourceInfo{
		ResourceID: "dispatcher-fw-cs-job", Kind: adapter.ResourceFirewall,
		Tags: map[string]string{"dispatcher": "true"},
	})
	assert.True(t, containsCall(*calls, "gcloud",
		"compute", "firewall-rules", "delete", "dispatcher-fw-cs-job", "--quiet", "--project", "p"))
}

func TestGCPListArtifactRegistryResources(t *testing.T) {
	arJSON := `[
	  {"name":"projects/p/locations/us-east1/repositories/dispatcher-cs","sizeBytes":"1073741824"},
	  {"name":"projects/p/locations/us/repositories/some-other-repo"}
	]`
	captureRunCLIWith(t, func(string, ...string) ([]byte, error) { return []byte(arJSON), nil })

	g := &GCPProvider{project: "p"}
	res, err := g.listArtifactRegistryResources(context.Background())
	require.NoError(t, err)
	require.Len(t, res, 1, "only dispatcher's own agent-image repo")
	assert.Equal(t, "dispatcher-cs", res[0].ResourceID)
	assert.Equal(t, adapter.ResourceContainerImage, res[0].Kind)
	assert.Equal(t, "us-east1", res[0].Region)
	assert.Equal(t, "", res[0].RunID, "shared infra → standing (surfaced), not auto-reaped")
	assert.True(t, res[0].DispatcherOwned())
	assert.Greater(t, res[0].MonthlyUSD, 0.0, "1 GiB of storage must show a nonzero monthly cost")
}

func TestGCPDestroyContainerImage(t *testing.T) {
	calls := captureRunCLI(t)
	g := &GCPProvider{project: "p"}
	_ = g.DestroyResource(context.Background(), adapter.ResourceInfo{
		ResourceID: "dispatcher-cs", Kind: adapter.ResourceContainerImage, Region: "us-east1",
		Tags: map[string]string{"dispatcher": "true"},
	})
	assert.True(t, containsCall(*calls, "gcloud",
		"artifacts", "repositories", "delete", "dispatcher-cs", "--location", "us-east1", "--quiet", "--project", "p"))
}
