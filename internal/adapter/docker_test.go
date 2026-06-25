package adapter

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDockerInspect(t *testing.T) {
	t.Run("OOM kill maps to SIGKILL", func(t *testing.T) {
		fd := parseDockerInspect("137|true|")
		assert.True(t, fd.OOMKilled)
		assert.Equal(t, "SIGKILL", fd.Signal)
		assert.Equal(t, "container OOM-killed", fd.Message)
		assert.Equal(t, 137, fd.ExitCode)
	})

	t.Run("non-zero exit with no error gets a synthesized message", func(t *testing.T) {
		fd := parseDockerInspect("7|false|")
		assert.Equal(t, 7, fd.ExitCode)
		assert.False(t, fd.OOMKilled)
		assert.Equal(t, "container exited with code 7", fd.Message)
	})

	t.Run("container error is preserved and truncated", func(t *testing.T) {
		long := strings.Repeat("x", 5000)
		fd := parseDockerInspect("1|false|" + long)
		assert.NotEmpty(t, fd.Message)
		assert.Less(t, len(fd.Message), len(long), "verbose error must be truncated (may carry secrets)")
	})

	t.Run("unexpected shape is reported, not panicked", func(t *testing.T) {
		fd := parseDockerInspect("garbage")
		assert.Contains(t, fd.Message, "unexpected shape")
	})
}
