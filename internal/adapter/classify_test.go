package adapter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyFailure(t *testing.T) {
	cases := []struct {
		name string
		in   FailureDetails
		want FailureKind
	}{
		{
			name: "OOM kill is transient",
			in:   FailureDetails{ExitCode: 137, OOMKilled: true, Signal: "SIGKILL"},
			want: FailureTransient,
		},
		{
			name: "SIGKILL without OOM flag still transient",
			in:   FailureDetails{Signal: "SIGKILL"},
			want: FailureTransient,
		},
		{
			name: "SIGTERM is transient (platform termination)",
			in:   FailureDetails{Signal: "SIGTERM"},
			want: FailureTransient,
		},
		{
			name: "non-zero exit with no signal is permanent (workload bug)",
			in:   FailureDetails{ExitCode: 1, Message: "exited with code 1"},
			want: FailurePermanent,
		},
		{
			name: "exit code 2 (typical syntax error) is permanent",
			in:   FailureDetails{ExitCode: 2, Message: "exited with code 2"},
			want: FailurePermanent,
		},
		{
			name: "empty details classify as unknown",
			in:   FailureDetails{},
			want: FailureUnknown,
		},
		{
			name: "adapter said something happened but no signal/code is permanent",
			in:   FailureDetails{Message: "docker inspect unavailable"},
			want: FailurePermanent,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ClassifyFailure(c.in))
		})
	}
}

// Adapters that only capture `$?` (the cloud SSH runner) can't set a Signal
// string, so a signal kill surfaces as an encoded exit code: the shell's
// 128+signal (137=SIGKILL, 143=SIGTERM) or a runtime's unsigned wrap of a
// negative return code (256-signal: 247=SIGKILL, 241=SIGTERM). A KILL/TERM there
// is environmental (OOM/preemption) → transient; a crash signal or an ordinary
// non-zero exit stays permanent.
func TestClassifyFailure_SignalExitCodes(t *testing.T) {
	cases := []struct {
		name string
		code int
		want FailureKind
	}{
		{"137 = 128+SIGKILL (probable OOM)", 137, FailureTransient},
		{"143 = 128+SIGTERM (platform kill)", 143, FailureTransient},
		{"247 = unsigned wrap of -SIGKILL (Python)", 247, FailureTransient},
		{"241 = unsigned wrap of -SIGTERM", 241, FailureTransient},
		{"139 = 128+SIGSEGV is a crash, permanent", 139, FailurePermanent},
		{"245 = unsigned wrap of -SIGSEGV, permanent", 245, FailurePermanent},
		{"130 = 128+SIGINT (user interrupt), permanent", 130, FailurePermanent},
		{"ordinary exit 1 stays permanent", 1, FailurePermanent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ClassifyFailure(FailureDetails{ExitCode: c.code, Message: "exited"}))
		})
	}
}

// TestClassifyFailure_RetryDecisionTable encodes the actual decision the
// executor makes — "should I retry this?" — so a future change to the
// classifier rules surfaces here.
func TestClassifyFailure_RetryDecisionTable(t *testing.T) {
	shouldRetry := func(d FailureDetails) bool {
		return ClassifyFailure(d) == FailureTransient
	}

	assert.True(t, shouldRetry(FailureDetails{OOMKilled: true}), "OOM should retry")
	assert.False(t, shouldRetry(FailureDetails{ExitCode: 1}), "syntax error should NOT retry")
	assert.False(t, shouldRetry(FailureDetails{}), "unknown should NOT retry (conservative)")
}
