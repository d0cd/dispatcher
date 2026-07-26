package cloudvm

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// gcpListResponses drives the runCLI seam with a canned JSON body per
// `gcloud compute <kind> list` call, keyed by the resource kind in argv[1].
func gcpListResponses(bodies map[string]string) func(string, ...string) ([]byte, error) {
	return func(_ string, args ...string) ([]byte, error) {
		if len(args) >= 3 && args[0] == "compute" && args[2] == "list" {
			if body, ok := bodies[args[1]]; ok {
				return []byte(body), nil
			}
			return []byte("[]"), nil
		}
		return []byte("[]"), nil
	}
}

func TestGCPProvider_ListResources_Argv(t *testing.T) {
	calls := captureRunCLIWith(t, gcpListResponses(nil))
	p := NewGCPProvider("proj", "us-central1-a")

	_, err := p.ListResources(context.Background())
	require.NoError(t, err)

	assert.True(t, containsCall(*calls, "gcloud", "compute", "instances", "list", "--format", "json", "--project", "proj"))
	assert.True(t, containsCall(*calls, "gcloud", "compute", "disks", "list", "--format", "json", "--project", "proj"))
	assert.True(t, containsCall(*calls, "gcloud", "compute", "images", "list", "--no-standard-images", "--format", "json", "--project", "proj"))
	assert.True(t, containsCall(*calls, "gcloud", "compute", "snapshots", "list", "--format", "json", "--project", "proj"))
	assert.True(t, containsCall(*calls, "gcloud", "compute", "addresses", "list", "--format", "json", "--project", "proj"))
}

func TestGCPProvider_ListResources_ParsesAndCosts(t *testing.T) {
	bodies := map[string]string{
		"instances": `[{"name":"vm1",
			"machineType":"https://www.googleapis.com/compute/v1/projects/proj/zones/us-central1-a/machineTypes/e2-medium",
			"status":"RUNNING",
			"zone":"https://www.googleapis.com/compute/v1/projects/proj/zones/us-central1-a",
			"labels":{"dispatcher":"true","dispatcher-run-id":"run_9"}}]`,
		"disks": `[{"name":"vm1-disk","sizeGb":"30",
			"type":"https://www.googleapis.com/compute/v1/projects/proj/zones/us-central1-a/diskTypes/pd-balanced",
			"zone":"https://www.googleapis.com/compute/v1/projects/proj/zones/us-central1-a",
			"labels":{"dispatcher":"true","dispatcher-run-id":"run_9"}}]`,
		"images":    `[{"name":"gpu-img","archiveSizeBytes":"2147483648","labels":{"dispatcher":"true"}}]`,
		"snapshots": `[{"name":"snap1","storageBytes":"5368709120","labels":{"owner":"other-team"}}]`,
		"addresses": `[{"name":"ip1","status":"RESERVED",
			"region":"https://www.googleapis.com/compute/v1/projects/proj/regions/us-central1",
			"labels":{"dispatcher":"true"}}]`,
	}
	captureRunCLIWith(t, gcpListResponses(bodies))
	p := NewGCPProvider("proj", "us-central1-a")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err)

	byID := map[string]adapter.ResourceInfo{}
	for _, r := range res {
		byID[r.ResourceID] = r
	}

	inst := byID["vm1"]
	assert.Equal(t, adapter.ResourceInstance, inst.Kind)
	assert.Equal(t, "us-central1-a", inst.Region)
	assert.Equal(t, "e2-medium", inst.InstanceType)
	assert.Equal(t, "run_9", inst.RunID)
	assert.True(t, inst.DispatcherOwned())
	assert.InDelta(t, 0.034*gcpMonthlyHours, inst.MonthlyUSD, 0.01)

	disk := byID["vm1-disk"]
	assert.Equal(t, adapter.ResourceDisk, disk.Kind)
	assert.Equal(t, "us-central1-a", disk.Region)
	assert.InDelta(t, 30*0.10, disk.MonthlyUSD, 0.01) // pd-balanced

	img := byID["gpu-img"]
	assert.Equal(t, adapter.ResourceImage, img.Kind)
	assert.Empty(t, img.RunID, "image has no run id -> standing")
	assert.InDelta(t, 2*0.05, img.MonthlyUSD, 0.001) // 2 GiB

	snap := byID["snap1"]
	assert.Equal(t, adapter.ResourceSnapshot, snap.Kind)
	assert.False(t, snap.DispatcherOwned(), "not dispatcher-owned -> external")
	assert.InDelta(t, 5*0.026, snap.MonthlyUSD, 0.001) // 5 GiB

	addr := byID["ip1"]
	assert.Equal(t, adapter.ResourceAddress, addr.Kind)
	assert.Equal(t, "us-central1", addr.Region)
	assert.Greater(t, addr.MonthlyUSD, 0.0, "a RESERVED (unused) static IP bills")
}

// A regional disk (region self-link, empty zone) and a global address (empty
// region) must parse to a usable location + scope tag so DestroyResource can
// pick --region / --global instead of an empty --zone/--region.
func TestGCPProvider_ListResources_RegionalDiskAndGlobalAddress(t *testing.T) {
	bodies := map[string]string{
		"disks": `[{"name":"rd","sizeGb":"50",
			"type":"https://www.googleapis.com/compute/v1/projects/proj/regions/us-central1/diskTypes/pd-balanced",
			"region":"https://www.googleapis.com/compute/v1/projects/proj/regions/us-central1","labels":{"dispatcher":"true"}}]`,
		"addresses": `[{"name":"ga","status":"RESERVED","labels":{"dispatcher":"true"}}]`, // no region -> global
	}
	captureRunCLIWith(t, gcpListResponses(bodies))
	res, err := NewGCPProvider("proj", "us-central1-a").ListResources(context.Background())
	require.NoError(t, err)

	byID := map[string]adapter.ResourceInfo{}
	for _, r := range res {
		byID[r.ResourceID] = r
	}
	rd := byID["rd"]
	assert.Equal(t, "us-central1", rd.Region, "regional disk location comes from the region self-link")
	assert.Equal(t, "regional", rd.Tags[gcpScopeTag])
	ga := byID["ga"]
	assert.Equal(t, "global", ga.Tags[gcpScopeTag], "an address with no region is global")
}

func TestGCPProvider_ListResources_SkipsTerminatedInstances(t *testing.T) {
	bodies := map[string]string{
		"instances": `[{"name":"dead","status":"TERMINATED","labels":{"dispatcher":"true"}}]`,
	}
	captureRunCLIWith(t, gcpListResponses(bodies))
	p := NewGCPProvider("proj", "us-central1-a")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err)
	for _, r := range res {
		assert.NotEqual(t, "dead", r.ResourceID, "a terminated instance is not a billable resource")
	}
}

func TestGCPProvider_ListResources_AuxKindErrorIsNonFatal(t *testing.T) {
	// A denied snapshots list must not blind gc to reapable instances.
	resp := func(_ string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[1] == "snapshots" {
			return nil, assert.AnError
		}
		if len(args) >= 3 && args[0] == "compute" && args[2] == "list" {
			if args[1] == "instances" {
				return []byte(`[{"name":"vm1","status":"RUNNING","labels":{"dispatcher":"true","dispatcher-run-id":"run_9"}}]`), nil
			}
		}
		return []byte("[]"), nil
	}
	captureRunCLIWith(t, resp)
	p := NewGCPProvider("proj", "us-central1-a")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err, "an auxiliary kind's error must not fail the whole enumeration")
	require.Len(t, res, 1)
	assert.Equal(t, "vm1", res[0].ResourceID)
}

func TestGCPProvider_DestroyResource_Argv(t *testing.T) {
	p := NewGCPProvider("proj", "us-central1-a")

	cases := []struct {
		name string
		res  adapter.ResourceInfo
		want []string
	}{
		{"instance",
			adapter.ResourceInfo{ResourceID: "vm1", Kind: adapter.ResourceInstance, Region: "us-central1-a"},
			[]string{"compute", "instances", "delete", "vm1", "--zone", "us-central1-a", "--quiet", "--project", "proj"}},
		{"disk",
			adapter.ResourceInfo{ResourceID: "d1", Kind: adapter.ResourceDisk, Region: "us-central1-a"},
			[]string{"compute", "disks", "delete", "d1", "--zone", "us-central1-a", "--quiet", "--project", "proj"}},
		{"image",
			adapter.ResourceInfo{ResourceID: "img1", Kind: adapter.ResourceImage},
			[]string{"compute", "images", "delete", "img1", "--quiet", "--project", "proj"}},
		{"snapshot",
			adapter.ResourceInfo{ResourceID: "s1", Kind: adapter.ResourceSnapshot},
			[]string{"compute", "snapshots", "delete", "s1", "--quiet", "--project", "proj"}},
		{"address",
			adapter.ResourceInfo{ResourceID: "a1", Kind: adapter.ResourceAddress, Region: "us-central1"},
			[]string{"compute", "addresses", "delete", "a1", "--region", "us-central1", "--quiet", "--project", "proj"}},
		{"regional-disk",
			adapter.ResourceInfo{ResourceID: "rd1", Kind: adapter.ResourceDisk, Region: "us-central1",
				Tags: map[string]string{gcpScopeTag: "regional"}},
			[]string{"compute", "disks", "delete", "rd1", "--region", "us-central1", "--quiet", "--project", "proj"}},
		{"global-address",
			adapter.ResourceInfo{ResourceID: "ga1", Kind: adapter.ResourceAddress,
				Tags: map[string]string{gcpScopeTag: "global"}},
			[]string{"compute", "addresses", "delete", "ga1", "--global", "--quiet", "--project", "proj"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := captureRunCLI(t)
			if tc.res.Tags == nil {
				tc.res.Tags = map[string]string{}
			}
			tc.res.Tags["dispatcher"] = "true" // owned; the adapter guards ownership
			_ = p.DestroyResource(context.Background(), tc.res)
			got := lastCall(t, calls)
			assert.Equal(t, "gcloud", got.name)
			assert.Equal(t, tc.want, got.args)
		})
	}
}

// gc must scan every accessible project so a dispatcher-owned resource leaked
// into another project is found. External (non-dispatcher) resources are only
// surfaced from the configured project so unrelated projects don't flood gc.
func TestGCPListResources_CrossProject(t *testing.T) {
	captureRunCLIWith(t, func(_ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "projects list"):
			return []byte(`[{"projectId":"proj-A"},{"projectId":"proj-other"}]`), nil
		case strings.Contains(joined, "instances list") && strings.Contains(joined, "proj-A"):
			return []byte(`[
			  {"name":"vm-a","status":"RUNNING","zone":"z/us-central1-a","machineType":"m/e2-small","labels":{"dispatcher":"true","dispatcher-run-id":"r1"}},
			  {"name":"ext-a","status":"RUNNING","zone":"z/us-central1-a","machineType":"m/e2-small","labels":{}}
			]`), nil
		case strings.Contains(joined, "instances list") && strings.Contains(joined, "proj-other"):
			return []byte(`[
			  {"name":"owned-other","status":"RUNNING","zone":"z/us-west1-a","machineType":"m/e2-small","labels":{"dispatcher":"true","dispatcher-run-id":"r2"}},
			  {"name":"ext-other","status":"RUNNING","zone":"z/us-west1-a","machineType":"m/e2-small","labels":{}}
			]`), nil
		}
		return []byte("[]"), nil
	})

	res, err := NewGCPProvider("proj-A", "us-central1-a").ListResources(context.Background())
	require.NoError(t, err)
	byName := map[string]adapter.ResourceInfo{}
	for _, r := range res {
		byName[r.ResourceID] = r
	}
	assert.Equal(t, "proj-A", byName["vm-a"].Scope, "configured-project owned resource carries its project")
	assert.Contains(t, byName, "ext-a", "external in the configured project stays visible")
	require.Contains(t, byName, "owned-other", "owned resource in another project is found")
	assert.Equal(t, "proj-other", byName["owned-other"].Scope)
	assert.NotContains(t, byName, "ext-other", "external in another project is not enumerated")
}

// Destroy must target the project the resource lives in, not the configured one.
func TestGCPDestroyResource_RoutesToProject(t *testing.T) {
	calls := captureRunCLIWith(t, func(_ string, _ ...string) ([]byte, error) { return []byte("{}"), nil })
	res := adapter.ResourceInfo{
		Kind: adapter.ResourceInstance, ResourceID: "vm-x", Region: "us-west1-a",
		Provider: string(ProviderGCP), Scope: "proj-other",
		Tags: map[string]string{"dispatcher": "true"},
	}
	require.NoError(t, NewGCPProvider("proj-A", "us-central1-a").DestroyResource(context.Background(), res))
	assert.True(t, containsCall(*calls, "gcloud", "compute", "instances", "delete", "vm-x", "--zone", "us-west1-a", "--quiet", "--project", "proj-other"),
		"delete routes to the resource's project")
}

// If projects can't be listed (no resourcemanager.projects.list), gc falls back
// to the configured project rather than failing.
func TestGCPListResources_ProjectListForbiddenFallsBack(t *testing.T) {
	captureRunCLIWith(t, func(_ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "projects list") {
			return nil, assert.AnError
		}
		if strings.Contains(joined, "instances list") {
			return []byte(`[{"name":"vm-a","status":"RUNNING","zone":"z/us-central1-a","machineType":"m/e2-small","labels":{"dispatcher":"true"}}]`), nil
		}
		return []byte("[]"), nil
	})
	res, err := NewGCPProvider("proj-A", "us-central1-a").ListResources(context.Background())
	require.NoError(t, err, "a forbidden project list must not fail the configured-project scan")
	require.Len(t, res, 1)
	assert.Equal(t, "vm-a", res[0].ResourceID)
}
