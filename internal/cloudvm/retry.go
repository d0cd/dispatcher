package cloudvm

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/dlog"
)

// RetryPolicy controls exponential backoff retry attempts.
type RetryPolicy struct {
	MaxAttempts int
	Initial     time.Duration
	Max         time.Duration
}

// DefaultRetry is the retry policy used by cloud provider calls.
var DefaultRetry = RetryPolicy{MaxAttempts: 4, Initial: 500 * time.Millisecond, Max: 8 * time.Second}

// Retry runs op until it succeeds, the context is canceled, or attempts are
// exhausted. The classifier decides whether a given error is transient and
// worth retrying. Non-transient errors return immediately.
func Retry(ctx context.Context, p RetryPolicy, classifier func(error) bool, op func() error) error {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = 1
	}
	delay := p.Initial
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}

	var err error
	for attempt := 0; attempt < p.MaxAttempts; attempt++ {
		err = op()
		if err == nil {
			return nil
		}
		if !classifier(err) || attempt == p.MaxAttempts-1 {
			return err
		}
		dlog.L().Warn("retry.transient", "attempt", attempt+1, "delay", delay.String(), "err", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
		if delay > p.Max && p.Max > 0 {
			delay = p.Max
		}
	}
	return err
}

// retryCLIOutput runs `bin args...`, capturing stdout, retrying transient
// failures per DefaultRetry. label is used to wrap stderr so IsTransient can
// classify on the CLI's actual complaint. Shared by every provider's CreateVM
// so the retry/exec/error-wrap behavior stays identical across them.
var retryCLIOutput = func(ctx context.Context, bin, label string, args ...string) ([]byte, error) {
	var out []byte
	err := Retry(ctx, DefaultRetry, IsTransient, func() error {
		var runErr error
		out, runErr = exec.CommandContext(ctx, bin, args...).Output()
		if runErr != nil {
			return wrapExecError(label, runErr)
		}
		return nil
	})
	return out, err
}

// runCLI executes a provider CLI and returns its stdout. It is a package-level
// seam so tests can capture the exact argv and stub output without invoking a
// real cloud binary — the teardown/list/get command lines are cost-critical and
// must not regress. On failure it returns a cliError carrying the CLI's stderr,
// so every caller surfaces the real complaint instead of "exit status N" even
// when it wraps the error with plain fmt.Errorf.
var runCLI = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return out, newCLIError(err)
	}
	return out, nil
}

// cliError carries a cloud CLI's stderr alongside the underlying exec error so
// its Error() surfaces the actual complaint. runCLI returns one on every
// failure; wrapExecError recognises it and won't append the stderr twice.
type cliError struct {
	stderr string
	err    error
}

func (e *cliError) Error() string {
	if e.stderr != "" {
		return e.stderr + ": " + e.err.Error()
	}
	return e.err.Error()
}

func (e *cliError) Unwrap() error { return e.err }

// isVMNotFound reports whether a provider CLI error means the VM no longer
// exists (as opposed to a transient/auth failure). GetVM maps this to
// State=Terminated,nil per the Provider contract; every other error propagates.
// It matches on the CLI's stderr, now carried by cliError.
func isVMNotFound(err error, vmID string) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	// Key off the VM id: a not-found that doesn't name this VM is about something
	// else (a missing CLI binary → "executable file not found"; a wrong resource
	// group → "resource group 'X' could not be found") and must NOT be read as the
	// VM being gone — that would stop teardown and leak a live, billing VM.
	if vmID != "" && !strings.Contains(s, strings.ToLower(vmID)) {
		return false
	}
	for _, marker := range []string{"not found", "notfound", "does not exist", "could not be found"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// newCLIError wraps a failed exec in a cliError when stderr is available.
func newCLIError(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return &cliError{stderr: strings.TrimSpace(string(ee.Stderr)), err: err}
	}
	return err
}

// wrapExecError prefixes a label and, for a raw *exec.ExitError, appends stderr
// so the classifier sees the cloud CLI's actual complaint, not just "exit status
// 1". It is idempotent over a cliError (which already carries stderr), so
// callers that wrap a runCLI result don't get the stderr twice.
func wrapExecError(label string, err error) error {
	var ce *cliError
	if errors.As(err, &ce) {
		return fmt.Errorf("%s: %w", label, err)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%s: %s: %w", label, strings.TrimSpace(string(ee.Stderr)), err)
	}
	return fmt.Errorf("%s: %w", label, err)
}

// IsTransient classifies HTTP/CLI errors that are safe to retry. Matches on
// stringy markers (no provider-specific exception types) since dispatcher
// shells out to cloud CLIs and parses their stderr.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, m := range []string{
		"throttl", // throttled, throttling
		"too many requests",
		"timeout",
		"timed out",
		"temporarily unavailable",
		"connection reset",
		"connection refused",
		"i/o timeout",
		"503 ",
		"504 ",
		"502 ",
		"500 ",
		"rate limit",
	} {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

// adoptCreatedVM makes CreateVM idempotent under the retry-then-"already exists"
// failure: a create CLI can create the instance server-side, then return a
// transient error, so the retry re-issues create and gets a non-transient
// "already exists" that surfaces as a failed run while the (dispatcher-tagged) VM
// keeps billing. Before surfacing such an error, look up the run-tagged VM and, if
// exactly one exists, adopt it (hydrated via GetVM). Returns nil if nothing was
// created (a genuine create failure), so the caller surfaces the original error.
func adoptCreatedVM(ctx context.Context, p Provider, runID string) *VMInfo {
	if runID == "" {
		return nil
	}
	vms, err := p.ListVMs(ctx, map[string]string{"dispatcher-run-id": runID})
	if err != nil || len(vms) != 1 {
		return nil
	}
	full, err := p.GetVM(ctx, vms[0].ID)
	if err != nil || full == nil {
		return nil
	}
	dlog.L().Warn("createvm.adopted", "run", runID, "vm_id", full.ID,
		"note", "create reported an error but the instance exists; adopting it instead of leaking")
	return full
}
