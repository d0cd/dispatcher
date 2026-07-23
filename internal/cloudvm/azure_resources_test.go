package cloudvm

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// A transient failure deleting a BILLING satellite (OS disk / public IP) must be
// retried and, if it persists, surfaced — otherwise teardown silently leaks an
// untagged disk that bills forever and gc can't reap.
func TestAzureDeleteAssociated_RetriesAndSurfacesBillingLeak(t *testing.T) {
	prev := runCLI
	t.Cleanup(func() { runCLI = prev })
	diskCalls := 0
	runCLI = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "delete") && strings.Contains(joined, "osdisk") {
			diskCalls++
			return nil, fmt.Errorf("Too many requests (throttled)") // transient, persistent
		}
		return []byte("{}"), nil
	}
	a := &AzureProvider{resourceGroup: "rg"}
	err := a.deleteAssociatedResources(context.Background(), azureVMResources{
		nicIDs: []string{"/nics/n1"}, publicIPs: []string{"/ips/p1"},
		osDiskID: "/disks/osdisk", vnets: []string{"/vnets/v1"},
	})
	require.Error(t, err, "a persistently-failing OS disk delete must surface, not be swallowed")
	assert.Contains(t, err.Error(), "osdisk")
	assert.Greater(t, diskCalls, 1, "the transient disk delete must be retried")
}

// azResponses drives the runCLI seam for az. It matches on the leading argv
// tokens so a test can canned-respond per subcommand (vm show, nic show, etc.).
func azResponses(match func(args []string) ([]byte, bool)) func(string, ...string) ([]byte, error) {
	return func(_ string, args ...string) ([]byte, error) {
		if body, ok := match(args); ok {
			return body, nil
		}
		// `show` returns a JSON object, `list` an array. Default the unmatched
		// shape so teardown's gatherVMResources (az vm show) parses it instead of
		// aborting the delete to avoid an untagged-satellite leak.
		if len(args) >= 2 && args[1] == "show" {
			return []byte("{}"), nil
		}
		return []byte("[]"), nil
	}
}

// az vm delete leaves the OS disk, NIC, public IP, and NSG behind. DestroyVM
// must cascade-delete them so a teardown stops leaking billable resources.
func TestAzureDestroyVM_CascadesAssociatedResources(t *testing.T) {
	calls := captureRunCLIWith(t, azResponses(func(args []string) ([]byte, bool) {
		if len(args) >= 2 && args[0] == "vm" && args[1] == "show" {
			return []byte(`{"storageProfile":{"osDisk":{"managedDisk":{"id":"disk-1"}}},
				"networkProfile":{"networkInterfaces":[{"id":"nic-1"}]}}`), true
		}
		if len(args) >= 3 && args[0] == "network" && args[1] == "nic" && args[2] == "show" {
			return []byte(`{"ipConfigurations":[{"publicIPAddress":{"id":"ip-1"},
				"subnet":{"id":"/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/default"}}],
				"networkSecurityGroup":{"id":"nsg-1"}}`), true
		}
		return nil, false
	}))

	err := NewAzureProvider("rg", "eastus").DestroyVM(context.Background(), "vm1")
	require.NoError(t, err)

	assert.True(t, containsCall(*calls, "az", "vm", "delete", "--resource-group", "rg", "--name", "vm1", "--yes", "--force-deletion", "true"),
		"the VM itself is deleted")
	// NIC/IP/NSG/disk plus the auto-created VNet (derived from the subnet id).
	for _, id := range []string{"nic-1", "ip-1", "nsg-1", "disk-1",
		"/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-1"} {
		assert.True(t, containsCall(*calls, "az", "resource", "delete", "--ids", id),
			"associated resource %s must be cascade-deleted", id)
	}
}

// A SKU restricted for the subscription is reported unavailable (so CreateVM can
// surface a clear error instead of the CLI's masked crash); an unrestricted one
// is available; an inconclusive probe defaults to available (never blocks).
func TestAzureSKUAvailable(t *testing.T) {
	captureRunCLIWith(t, func(_ string, _ ...string) ([]byte, error) {
		return []byte(`[{"name":"Standard_B2s","restrictions":[{"reasonCode":"NotAvailableForSubscription"}]}]`), nil
	})
	ok, reason := azureSKUAvailable(context.Background(), "eastus", "Standard_B2s")
	assert.False(t, ok)
	assert.Contains(t, reason, "subscription")

	captureRunCLIWith(t, func(_ string, _ ...string) ([]byte, error) {
		return []byte(`[{"name":"Standard_D2s_v7","restrictions":[]}]`), nil
	})
	ok, _ = azureSKUAvailable(context.Background(), "eastus", "Standard_D2s_v7")
	assert.True(t, ok)
}

// When the requested size is restricted, the fallback picks the smallest
// available general-purpose size that meets the requested vCPU/memory, and
// excludes GPU/HPC families.
func TestFirstAvailableAzureSKU(t *testing.T) {
	captureRunCLIWith(t, func(_ string, _ ...string) ([]byte, error) {
		return []byte(`[
		  {"name":"Standard_B2s","capabilities":[{"name":"vCPUs","value":"2"},{"name":"MemoryGB","value":"4"}],"restrictions":[{"reasonCode":"NotAvailableForSubscription"}]},
		  {"name":"Standard_D4als_v7","capabilities":[{"name":"vCPUs","value":"4"},{"name":"MemoryGB","value":"16"}],"restrictions":[]},
		  {"name":"Standard_D2als_v7","capabilities":[{"name":"vCPUs","value":"2"},{"name":"MemoryGB","value":"8"}],"restrictions":[]},
		  {"name":"Standard_NC4as_T4_v3","capabilities":[{"name":"vCPUs","value":"4"},{"name":"MemoryGB","value":"28"}],"restrictions":[]}
		]`), nil
	})
	alt, err := firstAvailableAzureSKU(context.Background(), "eastus", "Standard_B2s")
	require.NoError(t, err)
	assert.Equal(t, "Standard_D2als_v7", alt)
}

func TestFirstAvailableAzureSKU_NoneAvailable(t *testing.T) {
	captureRunCLIWith(t, func(_ string, _ ...string) ([]byte, error) {
		return []byte(`[
		  {"name":"Standard_B2s","capabilities":[{"name":"vCPUs","value":"2"},{"name":"MemoryGB","value":"4"}],"restrictions":[{"reasonCode":"NotAvailableForSubscription"}]},
		  {"name":"Standard_NC4as_T4_v3","capabilities":[{"name":"vCPUs","value":"4"},{"name":"MemoryGB","value":"28"}],"restrictions":[]}
		]`), nil
	})
	_, err := firstAvailableAzureSKU(context.Background(), "eastus", "Standard_B2s")
	require.Error(t, err)
}

// End-to-end control flow: a restricted GENERAL-PURPOSE size is masked by az as a
// "content already consumed" crash; CreateVM probes availability, substitutes the
// smallest available general-purpose size, and retries the create with it.
func TestAzureCreateVM_SubstitutesRestrictedGeneralPurpose(t *testing.T) {
	captureRunCLIWith(t, func(_ string, args ...string) ([]byte, error) {
		if slices.Contains(args, "list-skus") {
			if slices.Contains(args, "--size") { // availability probe
				return []byte(`[{"name":"Standard_B2s","restrictions":[{"reasonCode":"NotAvailableForSubscription"}]}]`), nil
			}
			return []byte(`[
				{"name":"Standard_B2s","capabilities":[{"name":"vCPUs","value":"2"},{"name":"MemoryGB","value":"4"}],"restrictions":[{"reasonCode":"NotAvailableForSubscription"}]},
				{"name":"Standard_D2als_v7","capabilities":[{"name":"vCPUs","value":"2"},{"name":"MemoryGB","value":"8"}],"restrictions":[]}
			]`), nil
		}
		return []byte("[]"), nil // adoptCreatedVM's vm-list probe: none
	})

	var createSizes []string
	prev := retryCLIOutput
	retryCLIOutput = func(_ context.Context, _, _ string, args ...string) ([]byte, error) {
		for i, a := range args {
			if a == "--size" && i+1 < len(args) {
				createSizes = append(createSizes, args[i+1])
			}
		}
		if len(createSizes) == 1 { // first create: the masked restriction crash
			return nil, errors.New("The content for this response was already consumed")
		}
		return []byte(`{"id":"/subscriptions/x/vm","publicIpAddress":"203.0.113.9"}`), nil
	}
	t.Cleanup(func() { retryCLIOutput = prev })

	vm, err := NewAzureProvider("rg", "eastus").CreateVM(context.Background(), VMOptions{
		Region: "eastus", InstanceType: "Standard_B2s",
		Tags: map[string]string{"dispatcher-run-id": "r"},
	})
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.9", vm.IP)
	require.Len(t, createSizes, 2)
	assert.Equal(t, "Standard_B2s", createSizes[0])
	assert.Equal(t, "Standard_D2als_v7", createSizes[1], "retry uses the available general-purpose substitute")
}

// A restricted GPU (N-series) size must fail closed with the actionable reason,
// never be silently substituted onto a CPU-only general-purpose VM.
func TestAzureCreateVM_FailsClosedForGPURequest(t *testing.T) {
	captureRunCLIWith(t, func(_ string, args ...string) ([]byte, error) {
		if slices.Contains(args, "list-skus") && slices.Contains(args, "--size") {
			return []byte(`[{"name":"Standard_NC6","restrictions":[{"reasonCode":"NotAvailableForSubscription"}]}]`), nil
		}
		return []byte("[]"), nil
	})
	creates := 0
	prev := retryCLIOutput
	retryCLIOutput = func(_ context.Context, _, _ string, _ ...string) ([]byte, error) {
		creates++
		return nil, errors.New("The content for this response was already consumed")
	}
	t.Cleanup(func() { retryCLIOutput = prev })

	_, err := NewAzureProvider("rg", "eastus").CreateVM(context.Background(), VMOptions{
		Region: "eastus", InstanceType: "Standard_NC6",
		Tags: map[string]string{"dispatcher-run-id": "r"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "choose a different")
	assert.Equal(t, 1, creates, "a GPU request must not be retried with a general-purpose substitute")
}

func TestAzureProvider_ListResources_Argv(t *testing.T) {
	calls := captureRunCLIWith(t, azResponses(func([]string) ([]byte, bool) { return nil, false }))
	p := NewAzureProvider("rg", "eastus")

	_, err := p.ListResources(context.Background())
	require.NoError(t, err)

	assert.True(t, containsCall(*calls, "az", "vm", "list", "--resource-group", "rg", "--show-details", "--output", "json"))
	assert.True(t, containsCall(*calls, "az", "disk", "list", "--resource-group", "rg", "--output", "json"))
	assert.True(t, containsCall(*calls, "az", "network", "public-ip", "list", "--resource-group", "rg", "--output", "json"))
	assert.True(t, containsCall(*calls, "az", "snapshot", "list", "--resource-group", "rg", "--output", "json"))
}

func TestAzureProvider_ListResources_ParsesAndCosts(t *testing.T) {
	match := func(args []string) ([]byte, bool) {
		switch {
		case len(args) >= 2 && args[0] == "vm" && args[1] == "list":
			return []byte(`[{"name":"vm1","powerState":"VM running","hardwareProfile":{"vmSize":"Standard_B2s"},
				"tags":{"dispatcher":"true","dispatcher-run-id":"run_9"}}]`), true
		case len(args) >= 2 && args[0] == "disk" && args[1] == "list":
			return []byte(`[{"name":"vm1_OsDisk","diskSizeGb":30,"sku":{"name":"Premium_LRS"},"managedBy":"vm1","tags":{}}]`), true
		case len(args) >= 3 && args[0] == "network" && args[1] == "public-ip" && args[2] == "list":
			return []byte(`[{"name":"vm1-ip","tags":{}}]`), true
		case len(args) >= 2 && args[0] == "snapshot" && args[1] == "list":
			return []byte(`[{"name":"snap1","diskSizeGb":50,"tags":{"dispatcher":"true"}}]`), true
		}
		return nil, false
	}
	captureRunCLIWith(t, azResponses(match))
	p := NewAzureProvider("rg", "eastus")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err)

	byID := map[string]adapter.ResourceInfo{}
	for _, r := range res {
		byID[r.ResourceID] = r
	}

	vm := byID["vm1"]
	assert.Equal(t, adapter.ResourceInstance, vm.Kind)
	assert.Equal(t, "run_9", vm.RunID)
	assert.True(t, vm.DispatcherOwned())
	assert.Greater(t, vm.MonthlyUSD, 0.0)

	disk := byID["vm1_OsDisk"]
	assert.Equal(t, adapter.ResourceDisk, disk.Kind)
	assert.False(t, disk.DispatcherOwned(), "the auto-created OS disk is untagged -> external")
	assert.InDelta(t, 30*0.135, disk.MonthlyUSD, 0.01) // Premium_LRS

	ip := byID["vm1-ip"]
	assert.Equal(t, adapter.ResourceAddress, ip.Kind)
	assert.Greater(t, ip.MonthlyUSD, 0.0, "an unattached public IP bills")

	snap := byID["snap1"]
	assert.Equal(t, adapter.ResourceSnapshot, snap.Kind)
	assert.InDelta(t, 50*0.05, snap.MonthlyUSD, 0.01)
}

func TestAzureProvider_ListResources_AuxKindErrorIsNonFatal(t *testing.T) {
	resp := func(_ string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "disk" && args[1] == "list" {
			return nil, assert.AnError
		}
		if len(args) >= 2 && args[0] == "vm" && args[1] == "list" {
			return []byte(`[{"name":"vm1","powerState":"VM running","hardwareProfile":{"vmSize":"Standard_B2s"},"tags":{"dispatcher":"true"}}]`), nil
		}
		return []byte("[]"), nil
	}
	captureRunCLIWith(t, resp)
	p := NewAzureProvider("rg", "eastus")

	res, err := p.ListResources(context.Background())
	require.NoError(t, err, "an auxiliary kind's error must not fail the whole enumeration")
	require.Len(t, res, 1)
	assert.Equal(t, "vm1", res[0].ResourceID)
}

func TestAzureProvider_DestroyResource_Argv(t *testing.T) {
	p := NewAzureProvider("rg", "eastus")

	cases := []struct {
		name string
		res  adapter.ResourceInfo
		want []string
	}{
		{"disk",
			adapter.ResourceInfo{ResourceID: "d1", Kind: adapter.ResourceDisk},
			[]string{"disk", "delete", "--resource-group", "rg", "--name", "d1", "--yes"}},
		{"address",
			adapter.ResourceInfo{ResourceID: "ip1", Kind: adapter.ResourceAddress},
			[]string{"network", "public-ip", "delete", "--resource-group", "rg", "--name", "ip1"}},
		{"snapshot",
			adapter.ResourceInfo{ResourceID: "s1", Kind: adapter.ResourceSnapshot},
			[]string{"snapshot", "delete", "--resource-group", "rg", "--name", "s1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := captureRunCLI(t)
			tc.res.Tags = map[string]string{"dispatcher": "true"} // owned; the adapter guards ownership
			_ = p.DestroyResource(context.Background(), tc.res)
			got := lastCall(t, calls)
			assert.Equal(t, "az", got.name)
			assert.Equal(t, tc.want, got.args)
		})
	}
}

// An instance goes through DestroyVM so the associated-resource cascade runs.
func TestAzureProvider_DestroyResource_InstanceUsesCascade(t *testing.T) {
	calls := captureRunCLIWith(t, azResponses(func([]string) ([]byte, bool) { return nil, false }))
	p := NewAzureProvider("rg", "eastus")

	_ = p.DestroyResource(context.Background(), adapter.ResourceInfo{ResourceID: "vm1", Kind: adapter.ResourceInstance, Tags: map[string]string{"dispatcher": "true"}})
	assert.True(t, containsCall(*calls, "az", "vm", "delete", "--resource-group", "rg", "--name", "vm1", "--yes", "--force-deletion", "true"))
}
