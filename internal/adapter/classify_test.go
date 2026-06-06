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
