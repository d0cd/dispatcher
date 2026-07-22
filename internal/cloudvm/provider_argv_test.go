package cloudvm

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// cliCall records one invocation of the runCLI seam.
type cliCall struct {
	name string
	args []string
}

// captureRunCLI replaces the runCLI seam with a recorder that returns a sentinel
// error, so a provider method's argv can be asserted without invoking a real
// cloud binary. The method's own error is irrelevant to these tests — they only
// pin the exact command line each operation sends.
func captureRunCLI(t *testing.T) *[]cliCall {
	return captureRunCLIWith(t, func(string, ...string) ([]byte, error) { return nil, assert.AnError })
}

// captureRunCLIWith is captureRunCLI with a caller-supplied response, so a test
// can drive a provider down its success path (e.g. a describe that returns a
// run id) instead of failing at the first call.
func captureRunCLIWith(t *testing.T, resp func(name string, args ...string) ([]byte, error)) *[]cliCall {
	t.Helper()
	var mu sync.Mutex
	var calls []cliCall
	prev := runCLI
	runCLI = func(_ context.Context, name string, args ...string) ([]byte, error) {
		// Providers may enumerate regions concurrently, so the recorder must be
		// safe for parallel calls.
		mu.Lock()
		calls = append(calls, cliCall{name: name, args: append([]string(nil), args...)})
		mu.Unlock()
		return resp(name, args...)
	}
	t.Cleanup(func() { runCLI = prev })
	return &calls
}

// containsCall reports whether the recorded invocations include an exact
// (name, args) match — used where an operation issues several seamed commands.
func containsCall(calls []cliCall, name string, args ...string) bool {
	for _, c := range calls {
		if c.name == name && slices.Equal(c.args, args) {
			return true
		}
	}
	return false
}

// lastCall returns the final recorded invocation — the operation under test.
// (GCP's Get/Destroy first resolve the zone via runCLI, so the operation's own
// command line is the last one recorded.)
func lastCall(t *testing.T, calls *[]cliCall) cliCall {
	t.Helper()
	if len(*calls) == 0 {
		t.Fatal("runCLI was never called")
	}
	return (*calls)[len(*calls)-1]
}

// AWS run-instances has no name uniqueness, so a transient error after the
// instance exists would make the retry create a SECOND instance. A per-run
// --client-token makes the create idempotent (the retry returns the same
// instance instead of double-provisioning a billing VM).
func TestAWSCreateVM_PassesIdempotencyClientToken(t *testing.T) {
	// Stub the security-group setup so CreateVM reaches run-instances.
	captureRunCLIWith(t, func(_ string, args ...string) ([]byte, error) {
		switch {
		case slices.Contains(args, "describe-vpcs"):
			return []byte("vpc-123"), nil
		case slices.Contains(args, "create-security-group"):
			return []byte("sg-123"), nil
		default:
			return []byte(""), nil
		}
	})
	var runArgs []string
	prevRetry := retryCLIOutput
	retryCLIOutput = func(_ context.Context, _, _ string, args ...string) ([]byte, error) {
		runArgs = append([]string(nil), args...)
		return nil, assert.AnError // args already captured; final error is irrelevant
	}
	t.Cleanup(func() { retryCLIOutput = prevRetry })

	p := NewAWSProvider("us-east-1")
	_, _ = p.CreateVM(context.Background(), VMOptions{
		Region: "us-east-1", Image: "ami-123",
		Tags: map[string]string{"dispatcher": "true", "dispatcher-run-id": "plan_x"},
	})

	i := slices.Index(runArgs, "--client-token")
	if assert.GreaterOrEqual(t, i, 0, "run-instances must carry a --client-token for idempotent retries") {
		// Scoped to the run id AND this attempt's security group (sg-123), so a
		// spot-reclaim re-provision gets a distinct token instead of colliding.
		assert.Equal(t, "plan_x-123", runArgs[i+1])
	}
}

// The client token must be stable within one provisioning attempt (so the CLI's
// internal retries dedupe to one instance) but distinct across attempts (so a
// spot-reclaim re-provision, which creates a fresh security group, doesn't reuse
// the terminated instance's token and hit IdempotentParameterMismatch).
func TestAWSClientToken_DistinctPerAttempt(t *testing.T) {
	opts := VMOptions{Tags: map[string]string{"dispatcher-run-id": "run_abc"}}
	first := awsClientToken(opts, "sg-0aaa")
	second := awsClientToken(opts, "sg-0bbb")
	assert.NotEqual(t, first, second, "a fresh security group (new attempt) must yield a distinct token")
	assert.Equal(t, first, awsClientToken(opts, "sg-0aaa"), "same attempt must be stable for CLI-retry idempotency")
	assert.Contains(t, first, "run_abc")
	assert.LessOrEqual(t, len(first), 64, "AWS caps client tokens at 64 chars")
}

func TestAWSProvider_Argv(t *testing.T) {
	p := NewAWSProvider("us-east-1")

	t.Run("GetVM", func(t *testing.T) {
		calls := captureRunCLI(t)
		_, _ = p.GetVM(context.Background(), "i-123")
		got := lastCall(t, calls)
		assert.Equal(t, "aws", got.name)
		assert.Equal(t, []string{"ec2", "describe-instances", "--region", "us-east-1", "--instance-ids", "i-123", "--output", "json"}, got.args)
	})

	t.Run("DestroyVM", func(t *testing.T) {
		calls := captureRunCLI(t)
		_ = p.DestroyVM(context.Background(), "i-123")
		got := lastCall(t, calls)
		assert.Equal(t, "aws", got.name)
		assert.Equal(t, []string{"ec2", "terminate-instances", "--region", "us-east-1", "--instance-ids", "i-123"}, got.args)
	})

	t.Run("ListVMs", func(t *testing.T) {
		calls := captureRunCLI(t)
		_, _ = p.ListVMs(context.Background(), map[string]string{"dispatcher": "true"})
		got := lastCall(t, calls)
		assert.Equal(t, "aws", got.name)
		assert.Equal(t, []string{"ec2", "describe-instances", "--region", "us-east-1", "--output", "json", "--filters", "Name=tag:dispatcher,Values=true"}, got.args)
	})
}

func TestHetznerProvider_Argv(t *testing.T) {
	p := NewHetznerProvider("nbg1")

	t.Run("GetVM", func(t *testing.T) {
		calls := captureRunCLI(t)
		_, _ = p.GetVM(context.Background(), "42")
		got := lastCall(t, calls)
		assert.Equal(t, "hcloud", got.name)
		assert.Equal(t, []string{"server", "describe", "42", "-o", "json"}, got.args)
	})

	t.Run("DestroyVM", func(t *testing.T) {
		calls := captureRunCLI(t)
		_ = p.DestroyVM(context.Background(), "42")
		// Every hcloud invocation in the destroy path must go through the seam so
		// the test is hermetic — including the pre-delete describe that recovers
		// the run id for firewall/ssh-key cleanup. If that describe escaped the
		// seam it would shell out to a real hcloud with a deadline-less context.
		assert.True(t, containsCall(*calls, "hcloud", "server", "delete", "42"),
			"server delete must go through the seam")
		assert.True(t, containsCall(*calls, "hcloud", "server", "describe", "42", "-o", "json"),
			"the run-id lookup describe must go through the seam, not a real exec")
	})

	// On the success path DestroyVM also issues a firewall delete and an ssh-key
	// delete (gated on recovering a run id from the server's labels). All four
	// hcloud commands must go through the seam — otherwise a future revert of the
	// best-effort deletes to a real exec would shell out on teardown unnoticed.
	t.Run("DestroyVM_fullPathSeamed", func(t *testing.T) {
		calls := captureRunCLIWith(t, func(_ string, args ...string) ([]byte, error) {
			if len(args) >= 2 && args[0] == "server" && args[1] == "describe" {
				return []byte(`{"labels":{"dispatcher-run-id":"run-xyz"}}`), nil
			}
			return nil, nil
		})
		_ = p.DestroyVM(context.Background(), "42")
		assert.True(t, containsCall(*calls, "hcloud", "server", "delete", "42"),
			"server delete must go through the seam")
		assert.True(t, containsCall(*calls, "hcloud", "firewall", "delete", firewallNameFromString("run-xyz")),
			"best-effort firewall delete must go through the seam")
		assert.True(t, containsCall(*calls, "hcloud", "ssh-key", "delete", "dispatcher-run-xyz"),
			"best-effort ssh-key delete must go through the seam")
	})

	t.Run("ListVMs", func(t *testing.T) {
		calls := captureRunCLI(t)
		_, _ = p.ListVMs(context.Background(), map[string]string{"dispatcher": "true"})
		got := lastCall(t, calls)
		assert.Equal(t, "hcloud", got.name)
		assert.Equal(t, []string{"server", "list", "-o", "json", "--selector", "dispatcher=true"}, got.args)
	})
}

func TestGCPProvider_Argv(t *testing.T) {
	p := NewGCPProvider("proj", "us-central1-a")

	t.Run("GetVM", func(t *testing.T) {
		calls := captureRunCLI(t)
		_, _ = p.GetVM(context.Background(), "vm1")
		got := lastCall(t, calls)
		assert.Equal(t, "gcloud", got.name)
		assert.Equal(t, []string{"compute", "instances", "describe", "vm1", "--zone", "us-central1-a", "--format", "json", "--project", "proj"}, got.args)
	})

	t.Run("DestroyVM", func(t *testing.T) {
		calls := captureRunCLI(t)
		_ = p.DestroyVM(context.Background(), "vm1")
		got := lastCall(t, calls)
		assert.Equal(t, "gcloud", got.name)
		assert.Equal(t, []string{"compute", "instances", "delete", "vm1", "--zone", "us-central1-a", "--quiet", "--project", "proj"}, got.args)
	})

	t.Run("ListVMs", func(t *testing.T) {
		calls := captureRunCLI(t)
		_, _ = p.ListVMs(context.Background(), map[string]string{"dispatcher": "true"})
		got := lastCall(t, calls)
		assert.Equal(t, "gcloud", got.name)
		assert.Equal(t, []string{"compute", "instances", "list", "--format", "json", "--project", "proj", "--filter", "labels.dispatcher=true"}, got.args)
	})
}

func TestAzureProvider_Argv(t *testing.T) {
	p := NewAzureProvider("rg", "eastus")

	t.Run("GetVM", func(t *testing.T) {
		calls := captureRunCLI(t)
		_, _ = p.GetVM(context.Background(), "vmA")
		got := lastCall(t, calls)
		assert.Equal(t, "az", got.name)
		assert.Equal(t, []string{"vm", "show", "--resource-group", "rg", "--name", "vmA", "--show-details", "--output", "json"}, got.args)
	})

	t.Run("DestroyVM", func(t *testing.T) {
		// gatherVMResources' `az vm show` must succeed (return valid JSON) so
		// teardown proceeds to the delete rather than aborting to avoid an
		// untagged-satellite leak; the VM here has no satellites ({}).
		calls := captureRunCLIWith(t, func(string, ...string) ([]byte, error) { return []byte("{}"), nil })
		_ = p.DestroyVM(context.Background(), "vmA")
		got := lastCall(t, calls)
		assert.Equal(t, "az", got.name)
		assert.Equal(t, []string{"vm", "delete", "--resource-group", "rg", "--name", "vmA", "--yes", "--force-deletion", "true"}, got.args)
	})

	t.Run("ListVMs", func(t *testing.T) {
		calls := captureRunCLI(t)
		_, _ = p.ListVMs(context.Background(), map[string]string{"dispatcher": "true"})
		got := lastCall(t, calls)
		assert.Equal(t, "az", got.name)
		assert.Equal(t, []string{"vm", "list", "--resource-group", "rg", "--show-details", "--output", "json"}, got.args)
	})
}
