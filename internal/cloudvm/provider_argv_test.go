package cloudvm

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On a spot-reclaim re-provision the per-run SG can survive teardown (a terminated
// instance stops reporting its SG membership). CreateVM's SG setup must adopt the
// existing same-name group instead of failing on InvalidGroup.Duplicate.
func TestAWSCreateSSHSecurityGroup_AdoptsDuplicate(t *testing.T) {
	captureRunCLIWith(t, func(_ string, args ...string) ([]byte, error) {
		switch {
		case slices.Contains(args, "describe-vpcs"):
			return []byte("vpc-1"), nil
		case slices.Contains(args, "create-security-group"):
			return nil, errors.New("An error occurred (InvalidGroup.Duplicate) when calling the CreateSecurityGroup operation: the security group 'dispatcher-r' already exists")
		case slices.Contains(args, "describe-security-groups"):
			return []byte("sg-existing\n"), nil
		case slices.Contains(args, "authorize-security-group-ingress"):
			return nil, errors.New("An error occurred (InvalidPermission.Duplicate) when calling the AuthorizeSecurityGroupIngress operation: the specified rule already exists")
		default:
			return []byte(""), nil
		}
	})
	sg, err := awsCreateSSHSecurityGroup(context.Background(), "us-east-1", "dispatcher-r", "0.0.0.0/0",
		map[string]string{"dispatcher": "true"})
	require.NoError(t, err, "a duplicate SG on retry must be adopted, not fatal")
	assert.Equal(t, "sg-existing", sg)
}

func TestAWSInstanceArch(t *testing.T) {
	cases := map[string]string{
		"t3.micro":    "x86_64",
		"m5.large":    "x86_64",
		"g4dn.xlarge": "x86_64",
		"g5.xlarge":   "x86_64",
		"inf1.xlarge": "x86_64",
		"t4g.nano":    "arm64",
		"c7g.large":   "arm64",
		"m6gd.xlarge": "arm64",
		"im4gn.large": "arm64",
		"g5g.xlarge":  "arm64",
		"a1.medium":   "arm64",
		"x2gd.large":  "arm64",
	}
	for it, want := range cases {
		assert.Equal(t, want, awsInstanceArch(it), it)
	}
}

// A Graviton (arm64) instance the planner selects as cheapest must resolve the
// arm64 Ubuntu AMI, or run-instances fails with an architecture mismatch.
func TestAWSCreateVM_ARM64ResolvesArmAMI(t *testing.T) {
	var ssmName string
	captureRunCLIWith(t, func(_ string, args ...string) ([]byte, error) {
		switch {
		case slices.Contains(args, "get-parameter"):
			for i, a := range args {
				if a == "--name" && i+1 < len(args) {
					ssmName = args[i+1]
				}
			}
			return []byte("ami-arm64example"), nil
		case slices.Contains(args, "describe-vpcs"):
			return []byte("vpc-1"), nil
		case slices.Contains(args, "create-security-group"):
			return []byte("sg-1"), nil
		default:
			return []byte(""), nil
		}
	})
	prev := retryCLIOutput
	retryCLIOutput = func(_ context.Context, _, _ string, _ ...string) ([]byte, error) {
		return nil, assert.AnError // stop after image resolution; args already captured
	}
	t.Cleanup(func() { retryCLIOutput = prev })

	_, _ = NewAWSProvider("us-east-1").CreateVM(context.Background(), VMOptions{
		Region: "us-east-1", InstanceType: "t4g.nano",
		Tags: map[string]string{"dispatcher-run-id": "r"},
	})
	assert.Contains(t, ssmName, "arm64", "arm64 instance must resolve the arm64 AMI param")
}

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
		// run id + the first attempt counter (a fresh provider starts at 1).
		assert.Equal(t, "plan_x-1", runArgs[i+1])
	}
}

// The client token must be stable within one provisioning attempt (so the CLI's
// internal retries dedupe to one instance) but distinct across attempts (so a
// spot-reclaim re-provision launches a NEW instance). Uniqueness comes from the
// attempt counter, NOT the security-group id (a retry can adopt the same SG).
func TestAWSClientToken_DistinctPerAttempt(t *testing.T) {
	opts := VMOptions{Tags: map[string]string{"dispatcher-run-id": "run_abc"}}
	first := awsClientToken(opts, 1)
	second := awsClientToken(opts, 2)
	assert.NotEqual(t, first, second, "a later attempt must yield a distinct token")
	assert.Equal(t, first, awsClientToken(opts, 1), "same attempt must be stable for CLI-retry idempotency")
	assert.Contains(t, first, "run_abc")
	assert.LessOrEqual(t, len(first), 64, "AWS caps client tokens at 64 chars")
}

// Regression guard for the spot-reclaim retry path: two CreateVM calls on the
// same provider and run — even when the security group is the SAME (adopted on
// retry) — must send DISTINCT run-instances client tokens, or EC2 idempotency
// returns the reclaimed (terminated) instance and the retry never re-provisions.
func TestAWSCreateVM_DistinctTokenAcrossReprovision(t *testing.T) {
	captureRunCLIWith(t, func(_ string, args ...string) ([]byte, error) {
		switch {
		case slices.Contains(args, "get-parameter"):
			return []byte("ami-1"), nil
		case slices.Contains(args, "describe-vpcs"):
			return []byte("vpc-1"), nil
		case slices.Contains(args, "create-security-group"):
			return []byte("sg-SAME"), nil // same id both calls (models adoption)
		default:
			return []byte(""), nil
		}
	})
	var tokens []string
	prev := retryCLIOutput
	retryCLIOutput = func(_ context.Context, _, _ string, args ...string) ([]byte, error) {
		if i := slices.Index(args, "--client-token"); i >= 0 && i+1 < len(args) {
			tokens = append(tokens, args[i+1])
		}
		return nil, assert.AnError // token captured; the create's own error is irrelevant
	}
	t.Cleanup(func() { retryCLIOutput = prev })

	p := NewAWSProvider("us-east-1")
	opts := VMOptions{Region: "us-east-1", InstanceType: "t3.micro",
		Tags: map[string]string{"dispatcher-run-id": "run_z"}}
	_, _ = p.CreateVM(context.Background(), opts)
	_, _ = p.CreateVM(context.Background(), opts)

	require.Len(t, tokens, 2)
	assert.NotEqual(t, tokens[0], tokens[1], "a re-provision must get a fresh token even with the same SG")
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
