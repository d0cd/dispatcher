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

// wrapExecError appends stderr from an *exec.ExitError so the classifier can
// see the cloud CLI's actual complaint, not just "exit status 1".
func wrapExecError(label string, err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%s: %s: %w", label, string(ee.Stderr), err)
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
