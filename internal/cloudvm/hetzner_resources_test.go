package cloudvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// hcloudListResponses drives the runCLI seam with a canned JSON body per
// `hcloud <kind> list` call, keyed by the resource kind in argv[0].
func hcloudListResponses(bodies map[string]string) func(string, ...string) ([]byte, error) {
	return func(_ string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[1] == "list" {
			if body, ok := bodies[args[0]]; ok {
				return []byte(body), nil
			}
		}
		return []byte("[]"), nil
	}
}

func TestHetznerProvider_ListResources_Argv(t *testing.T) {
	calls := captureRunCLIWith(t, hcloudListResponses(nil))
	p := NewHetznerProvider("fsn1")

	_, err := p.ListResources(context.Background())
	require.NoError(t, err)

	assert.True(t, containsCall(*calls, "hcloud", "server", "list", "-o", "json"))
	assert.True(t, containsCall(*calls, "hcloud", "volume", "list", "-o", "json"))
	assert.True(t, containsCall(*calls, "hcloud", "primary-ip", "list", "-o", "json"))
	assert.True(t, containsCall(*calls, "hcloud", "floating-ip", "list", "-o", "json"))
	assert.True(t, containsCall(*calls, "hcloud", "image", "list", "--type", "snapshot", "-o", "json"))
	assert.True(t, containsCall(*calls, "hcloud", "firewall", "list", "--selector", "dispatcher=true", "-o", "json"))
}

func TestHetznerProvider_ListResources_ParsesAndCosts(t *testing.T) {
	bodies := map[string]string{
		"server": `[{"id":42,"name":"vm1","status":"running","server_type":{"name":"cax11"},
			"labels":{"dispatcher":"true","dispatcher-run-id":"run_9"}}]`,
		"volume":      `[{"id":7,"name":"data","size":100,"labels":{"owner":"other"}}]`,
		"primary-ip":  `[{"id":3,"name":"ip1","assignee_id":0,"labels":{}}]`,
		"floating-ip": `[{"id":5,"name":"fip1","labels":{}}]`,
		"image":       `[{"id":9,"description":"snap1","image_size":20,"labels":{"dispatcher":"true"}}]`,
		"firewall":    `[{"id":11,"name":"dispatcher-run_9","labels":{"dispatcher":"true","dispatcher-run-id":"run_9"}}]`,
	}
	captureRunCLIWith(t, hcloudListResponses(bodies))
	p := NewHetznerProvider("fsn1")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err)

	byID := map[string]adapter.ResourceInfo{}
	for _, r := range res {
		byID[r.ResourceID] = r
	}

	srv := byID["42"]
	assert.Equal(t, adapter.ResourceInstance, srv.Kind)
	assert.Equal(t, "cax11", srv.InstanceType)
	assert.Equal(t, "run_9", srv.RunID)
	assert.True(t, srv.DispatcherOwned())
	assert.Greater(t, srv.MonthlyUSD, 0.0)

	vol := byID["7"]
	assert.Equal(t, adapter.ResourceDisk, vol.Kind)
	assert.False(t, vol.DispatcherOwned())
	assert.Greater(t, vol.MonthlyUSD, 0.0)

	pip := byID["3"]
	assert.Equal(t, adapter.ResourceAddress, pip.Kind)
	assert.Greater(t, pip.MonthlyUSD, 0.0)

	fw := byID["11"]
	assert.Equal(t, adapter.ResourceFirewall, fw.Kind)
	assert.Equal(t, "run_9", fw.RunID)
	assert.True(t, fw.DispatcherOwned())
	assert.Equal(t, 0.0, fw.MonthlyUSD, "firewalls are free on Hetzner")
}

func TestHetznerProvider_ListResources_AuxKindErrorIsNonFatal(t *testing.T) {
	resp := func(_ string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "volume" && args[1] == "list" {
			return nil, assert.AnError
		}
		if len(args) >= 2 && args[0] == "server" && args[1] == "list" {
			return []byte(`[{"id":42,"name":"vm1","status":"running","server_type":{"name":"cax11"},"labels":{"dispatcher":"true"}}]`), nil
		}
		return []byte("[]"), nil
	}
	captureRunCLIWith(t, resp)
	p := NewHetznerProvider("fsn1")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err, "an auxiliary kind's error must not fail the whole enumeration")
	require.Len(t, res, 1)
	assert.Equal(t, "42", res[0].ResourceID)
}

func TestHetznerProvider_DestroyResource_Argv(t *testing.T) {
	p := NewHetznerProvider("fsn1")

	cases := []struct {
		name string
		res  adapter.ResourceInfo
		want []string
	}{
		{"volume",
			adapter.ResourceInfo{ResourceID: "7", Kind: adapter.ResourceDisk},
			[]string{"volume", "delete", "7"}},
		{"snapshot",
			adapter.ResourceInfo{ResourceID: "9", Kind: adapter.ResourceSnapshot},
			[]string{"image", "delete", "9"}},
		{"firewall",
			adapter.ResourceInfo{ResourceID: "11", Kind: adapter.ResourceFirewall},
			[]string{"firewall", "delete", "11"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := captureRunCLI(t)
			tc.res.Tags = map[string]string{"dispatcher": "true"} // owned; the adapter guards ownership
			_ = p.DestroyResource(context.Background(), tc.res)
			got := lastCall(t, calls)
			assert.Equal(t, "hcloud", got.name)
			assert.Equal(t, tc.want, got.args)
		})
	}
}

// DestroyResource routes each kind to the right hcloud verb (floating-ip vs
// primary-ip, instance -> server delete via the cascade), errors on an unknown
// kind, and refuses a resource dispatcher does not own.
func TestHetznerProvider_DestroyResource_RoutingAndGuard(t *testing.T) {
	p := NewHetznerProvider("fsn1")
	owned := map[string]string{"dispatcher": "true"}

	calls := captureRunCLI(t)
	_ = p.DestroyResource(context.Background(), adapter.ResourceInfo{
		ResourceID: "5", Kind: adapter.ResourceAddress, Tags: mergeTag(owned, hetznerIPKindTag, "floating-ip")})
	assert.True(t, containsCall(*calls, "hcloud", "floating-ip", "delete", "5"))

	calls = captureRunCLI(t)
	_ = p.DestroyResource(context.Background(), adapter.ResourceInfo{
		ResourceID: "3", Kind: adapter.ResourceAddress, Tags: owned}) // no ip-kind -> primary-ip
	assert.True(t, containsCall(*calls, "hcloud", "primary-ip", "delete", "3"))

	calls = captureRunCLI(t)
	_ = p.DestroyResource(context.Background(), adapter.ResourceInfo{
		ResourceID: "42", Kind: adapter.ResourceInstance, Tags: owned}) // routes through DestroyVM
	assert.True(t, containsCall(*calls, "hcloud", "server", "delete", "42"))

	// Unknown kind and CLI failure both surface an error.
	captureRunCLI(t)
	err := p.DestroyResource(context.Background(), adapter.ResourceInfo{ResourceID: "x", Kind: "bogus", Tags: owned})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot destroy")

	err = p.DestroyResource(context.Background(), adapter.ResourceInfo{ResourceID: "v", Kind: adapter.ResourceDisk})
	require.Error(t, err, "an unowned resource must be refused")
	assert.Contains(t, err.Error(), "not dispatcher-owned")
}

// A per-run firewall must be labeled dispatcher=true (and the run id) at
// creation so gc can recognize it as dispatcher-owned and reap a leaked one.
func TestHetznerFirewallCreateArgs_LabelsDispatcherOwned(t *testing.T) {
	args := hetznerFirewallCreateArgs("dispatcher-run_9",
		map[string]string{"dispatcher": "true", "dispatcher-run-id": "run_9"})
	joined := " " + joinArgs(args) + " "
	assert.Contains(t, joined, "firewall create")
	assert.Contains(t, joined, "--label dispatcher=true")
	assert.Contains(t, joined, "--label dispatcher-run-id=run_9")
}

func joinArgs(a []string) string {
	s := ""
	for i, x := range a {
		if i > 0 {
			s += " "
		}
		s += x
	}
	return s
}
