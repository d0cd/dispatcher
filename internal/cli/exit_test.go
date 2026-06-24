package cli

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveExitError(t *testing.T) {
	t.Run("nil error exits zero with no message", func(t *testing.T) {
		code, msg := ResolveExitError(nil)
		assert.Equal(t, 0, code)
		assert.Empty(t, msg)
	})

	// The bug this guards: a plain error returned by a SilenceErrors command
	// must still be surfaced to the user instead of a silent exit 1.
	t.Run("plain error is surfaced with exit 1", func(t *testing.T) {
		code, msg := ResolveExitError(errors.New(`invalid path "x"`))
		assert.Equal(t, 1, code)
		assert.Equal(t, `invalid path "x"`, msg)
	})

	t.Run("ExitError carries its code and message", func(t *testing.T) {
		code, msg := ResolveExitError(&ExitError{Code: 2, Err: errors.New("audit verdict: blocked")})
		assert.Equal(t, 2, code)
		assert.Equal(t, "audit verdict: blocked", msg)
	})

	// A command that already presented the failure (e.g. run's "Run failed:")
	// keeps its exit code but is not reprinted.
	t.Run("already-printed ExitError is not reprinted", func(t *testing.T) {
		code, msg := ResolveExitError(&ExitError{Code: 3, Err: errors.New("run failed"), AlreadyPrinted: true})
		assert.Equal(t, 3, code)
		assert.Empty(t, msg)
	})
}
