package adapter

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateFailureMessage_ShortPassesThrough(t *testing.T) {
	in := "container OOM-killed"
	assert.Equal(t, in, truncateFailureMessage(in))
}

func TestTruncateFailureMessage_LongIsTruncated(t *testing.T) {
	in := strings.Repeat("x", 500)
	out := truncateFailureMessage(in)
	// MaxFailureMessageLen rune cap plus ellipsis byte sequence.
	assert.Less(t, len(out), len(in))
	assert.True(t, strings.HasSuffix(out, "…"), "truncated output should end with ellipsis")
}

func TestTruncateFailureMessage_OnlyFirstLineKept(t *testing.T) {
	// Multi-line input — only the first non-empty line should survive.
	// Defense against verbose stderr dumps leaking workload-private data.
	in := "connect failed: password=hunter2\n  at frame 1\n  at frame 2\n"
	out := truncateFailureMessage(in)
	assert.NotContains(t, out, "frame", "later lines should be dropped")
	assert.Contains(t, out, "connect failed")
}

func TestTruncateFailureMessage_EmptyStays(t *testing.T) {
	assert.Empty(t, truncateFailureMessage(""))
	assert.Empty(t, truncateFailureMessage("\n\n"))
}
