package cloudvm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveZone must retry a transient list error rather than immediately
// collapsing to the default zone — otherwise a single throttle makes DestroyVM
// target the wrong zone and leak the VM.
func TestResolveZone_RetriesTransient(t *testing.T) {
	prev := DefaultRetry
	DefaultRetry = RetryPolicy{MaxAttempts: 3, Initial: time.Millisecond, Max: 2 * time.Millisecond}
	t.Cleanup(func() { DefaultRetry = prev })

	prevCLI := runCLI
	var calls int
	runCLI = func(context.Context, string, ...string) ([]byte, error) {
		calls++
		if calls < 2 {
			return nil, errors.New("503 Service Unavailable")
		}
		return []byte("us-west1-b\n"), nil
	}
	t.Cleanup(func() { runCLI = prevCLI })

	g := NewGCPProvider("proj", "us-central1-a")
	zone := g.resolveZone(context.Background(), "vm-1")
	assert.Equal(t, "us-west1-b", zone, "a transient list error is retried, not collapsed to the default zone")
	assert.Equal(t, 2, calls)
}

// TestCreateVMRetriesTransient covers C4: AWS/GCP/Azure CreateVM must route
// their CLI invocation through Retry, so a transient error (503) is retried
// MaxAttempts times rather than failing the run on the first attempt. A PATH
// stub stands in for the cloud CLI and counts invocations; DefaultRetry is
// shrunk so the backoff sleeps don't slow the test.
func TestCreateVMRetriesTransient(t *testing.T) {
	prev := DefaultRetry
	DefaultRetry = RetryPolicy{MaxAttempts: 3, Initial: time.Millisecond, Max: 2 * time.Millisecond}
	t.Cleanup(func() { DefaultRetry = prev })

	binDir := t.TempDir()
	countFile := filepath.Join(binDir, "count")
	stub := "#!/bin/sh\necho x >> \"" + countFile + "\"\necho '503 Service Unavailable' >&2\nexit 1\n"
	for _, name := range []string{"aws", "gcloud", "az"} {
		require.NoError(t, os.WriteFile(filepath.Join(binDir, name), []byte(stub), 0o755))
	}
	t.Setenv("PATH", binDir)

	cases := []struct {
		name     string
		provider Provider
	}{
		{"aws", NewAWSProvider("us-east-1")},
		{"gcp", NewGCPProvider("proj", "us-central1-a")},
		{"azure", NewAzureProvider("rg", "eastus")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(countFile, nil, 0o600))
			_, err := c.provider.CreateVM(context.Background(),
				VMOptions{Name: "n", Tags: map[string]string{"dispatcher": "true"}})
			require.Error(t, err)
			data, _ := os.ReadFile(countFile)
			assert.Equalf(t, DefaultRetry.MaxAttempts, strings.Count(string(data), "x"),
				"%s CreateVM should retry the transient error MaxAttempts times", c.name)
		})
	}
}

// TestValidateVMArgs covers S11: region/instance-type/image must be rejected
// when empty, flag-like (leading '-'), or carrying separator/quote chars,
// while legitimate provider-default values (including colon/slash-bearing
// image refs) pass.
func TestValidateVMArgs(t *testing.T) {
	ok := []struct{ region, itype, image string }{
		{"us-east-1", "t3.micro", "ami-0c7217cdde317cfec"},
		{"fsn1", "cax11", "ubuntu-24.04"},
		{"us-central1-a", "e2-medium", "ubuntu-2404-lts-amd64"},
		{"eastus", "Standard_B2s", "Canonical:ubuntu-24_04-lts:server:latest"},
		{"us-east-1", "t3.micro", "ghcr.io/org/img@sha256:abc"},
	}
	for _, c := range ok {
		assert.NoErrorf(t, validateVMArgs(c.region, c.itype, c.image),
			"expected %q/%q/%q to pass", c.region, c.itype, c.image)
	}

	bad := []struct {
		name                 string
		region, itype, image string
	}{
		{"leading-dash-region", "--foo", "t3.micro", "ami-x"},
		{"space-in-type", "us-east-1", "t3 micro", "ami-x"},
		{"comma-in-type", "us-east-1", "t3,micro", "ami-x"},
		{"empty-image", "us-east-1", "t3.micro", ""},
		{"newline-image", "us-east-1", "t3.micro", "ami-x\nhostNetwork"},
		{"quote-image", "us-east-1", "t3.micro", `ami"x`},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			assert.Error(t, validateVMArgs(c.region, c.itype, c.image))
		})
	}
}

// TestProviderRejectsBadTagsPreExec covers S6: each real provider validates
// tags before invoking any CLI, so a crafted tag value is rejected with a
// provider-named error rather than reaching exec. SSHKeyPath is left empty so
// Hetzner does not attempt its pre-validation ssh-key upload.
func TestProviderRejectsBadTagsPreExec(t *testing.T) {
	badTags := map[string]string{"k": "v,extra=injected"}
	cases := []struct {
		name     string
		provider Provider
		wantMsg  string
	}{
		{"aws", NewAWSProvider("us-east-1"), "aws tags"},
		{"gcp", NewGCPProvider("proj", "us-central1-a"), "gcp labels"},
		{"azure", NewAzureProvider("rg", "eastus"), "azure tags"},
		{"hetzner", NewHetznerProvider("fsn1"), "hetzner labels"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.provider.CreateVM(context.Background(), VMOptions{Name: "n", Tags: badTags})
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.wantMsg)
		})
	}
}

// --- S7: per-run firewall ---

func TestValidateFirewallCIDR(t *testing.T) {
	for _, ok := range []string{"203.0.113.4/32", "10.0.0.0/8", "0.0.0.0/0"} {
		assert.NoErrorf(t, validateFirewallCIDR(ok), "%q should be valid", ok)
	}
	for _, bad := range []string{"", "203.0.113.4", "not-a-cidr", "10.0.0.0/33"} {
		assert.Errorf(t, validateFirewallCIDR(bad), "%q should be rejected", bad)
	}
}

func TestFirewallNameFromString(t *testing.T) {
	assert.Equal(t, "dispatcher-fw-run-abc123", firewallNameFromString("run_abc123"))
	// Output is restricted to [a-z0-9-] (valid for Hetzner fw, GCP rule, GCP tag).
	for _, r := range firewallNameFromString("Run_AB.c/9") {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
		assert.Truef(t, ok, "unexpected char %q in firewall name", r)
	}
}

func TestHetznerFirewallArgs(t *testing.T) {
	assert.Equal(t, []string{"firewall", "create", "--name", "fw1"}, hetznerFirewallCreateArgs("fw1"))
	rule := hetznerFirewallRuleArgs("fw1", "203.0.113.4/32")
	assert.Contains(t, rule, "--source-ips")
	assert.Contains(t, rule, "22")
	// CIDR is a standalone argv token (no concatenation).
	assert.Equal(t, "203.0.113.4/32", rule[len(rule)-1])
}

// TestFirewallUnsupportedProviders covers the no-silent-failure rule: providers
// without a working per-run firewall reject a requested --allow-ssh-from (before
// any CLI call) rather than provisioning a VM with the firewall silently ignored
// or a no-op rule that implies SSH is locked down. GCP is included because an
// additive ALLOW rule cannot restrict the default network's default-allow-ssh.
func TestFirewallUnsupportedProviders(t *testing.T) {
	// AWS is intentionally absent: it now provisions a per-run security group
	// for SSH ingress instead of rejecting --allow-ssh-from.
	cases := []struct {
		name     string
		provider Provider
	}{
		{"azure", NewAzureProvider("rg", "eastus")},
		{"gcp", NewGCPProvider("proj", "us-central1-a")},
		{"lima", NewLimaProvider()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.provider.CreateVM(context.Background(), VMOptions{
				Name:         "n",
				AllowSSHFrom: "203.0.113.4/32",
				Tags:         map[string]string{"dispatcher": "true"},
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not yet supported")
			assert.Contains(t, err.Error(), c.name)
		})
	}
}

// TestKubernetesRejectsInjection covers S2: a tag or image value carrying a
// newline/quote must be rejected before the manifest is built, blocking
// Pod-spec injection.
func TestKubernetesRejectsInjection(t *testing.T) {
	k := NewKubernetesProvider("default")

	_, err := k.CreateVM(context.Background(), VMOptions{
		Name:  "job1",
		Image: "ubuntu:24.04\"\n      hostNetwork: true",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "image")

	_, err = k.CreateVM(context.Background(), VMOptions{
		Name:  "job1",
		Image: "ubuntu:24.04",
		Tags:  map[string]string{"evil": "x\n    privileged: true"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "labels")

	// The job name is also interpolated into the manifest and must be validated.
	_, err = k.CreateVM(context.Background(), VMOptions{
		Name:  "job1\n      hostNetwork: true",
		Image: "ubuntu:24.04",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "job name")
}

// TestBuildJobManifestSafeImage confirms a clean image still produces a valid
// manifest (no over-rejection of legitimate refs).
func TestBuildJobManifestSafeImage(t *testing.T) {
	k := NewKubernetesProvider("default")
	m := k.buildJobManifest("job1", "ghcr.io/org/img@sha256:abc", VMOptions{})
	assert.Contains(t, m, "image: ghcr.io/org/img@sha256:abc")
}

// TestCatalogKeepsSpeclessInstances covers C2: an instance with unknown specs
// (VCPUs/MemoryGB == 0, as live Azure rows arrive) must not be filtered out by
// the vCPU/memory minimums.
func TestCatalogKeepsSpeclessInstances(t *testing.T) {
	cat := &Catalog{instances: []InstanceType{{
		Name:         "Standard_B2s",
		Provider:     ProviderAzure,
		PricePerHour: 0.096,
		Arch:         "x86_64",
	}}}
	matches := cat.FindCheapestForProvider(ProviderAzure, InstanceRequirements{MinVCPUs: 2, MinMemoryGB: 4})
	require.Len(t, matches, 1)
	assert.Equal(t, "Standard_B2s", matches[0].Name)
}

// TestCatalogStillFiltersKnownSpecs ensures the C2 guard does not disable
// filtering for instances that DO carry specs.
func TestCatalogStillFiltersKnownSpecs(t *testing.T) {
	cat := &Catalog{instances: []InstanceType{{
		Name: "tiny", Provider: ProviderAWS, VCPUs: 1, MemoryGB: 1, PricePerHour: 0.01, Arch: "x86_64",
	}}}
	matches := cat.FindCheapestForProvider(ProviderAWS, InstanceRequirements{MinVCPUs: 2, MinMemoryGB: 4})
	assert.Empty(t, matches)
}

// sanity: bad-tag error messages never contain the injected payload verbatim
// in a way that suggests it reached argv (defensive).
func TestProviderTagErrorDoesNotExec(t *testing.T) {
	_, err := NewAWSProvider("us-east-1").CreateVM(context.Background(),
		VMOptions{Name: "n", Tags: map[string]string{"k": "v,x"}})
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), "run-instances"),
		"validation should fail before exec, not at the CLI")
}
