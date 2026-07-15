package adapter

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

// Count-mode shards share the same workload name and plan id, so the container
// name must incorporate the shard index — otherwise concurrent shards collide on
// one --name and all but the first fail "container name already in use".
func TestDockerContainerName_ShardIndexDisambiguates(t *testing.T) {
	w := types.WorkloadSpec{Name: "trainer"}

	plain := dockerContainerName(w, "plan_abc")
	assert.Equal(t, "dispatcher-trainer-plan_abc", plain, "no shard: name is unchanged")

	w0 := w
	w0.Env = map[string]string{"SHARD_INDEX": "0"}
	w1 := w
	w1.Env = map[string]string{"SHARD_INDEX": "1"}
	n0 := dockerContainerName(w0, "plan_abc")
	n1 := dockerContainerName(w1, "plan_abc")
	assert.NotEqual(t, n0, n1, "distinct shards must get distinct container names")
	assert.Contains(t, n0, "0")
	assert.Contains(t, n1, "1")
}

// A workload with a .env but no resolvable image must not orphan its plaintext
// env temp file: Execute returns an error before a dockerState is created, so
// nothing else will ever clean it up.
func TestDockerAdapter_EnvFileCleanedUpOnNoImageError(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp) // WriteSecureTempFile writes under os.TempDir()

	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, ".env"), []byte("SECRET=x\n"), 0o600))

	p := &types.Plan{
		Metadata: types.PlanMetadata{ID: "p1"},
		Workload: types.WorkloadSpec{
			Name:   "app",
			Source: types.WorkloadSource{Path: src},
			// No Dockerfile and no BaseImage → the "no image" error path.
		},
	}
	_, err := (&DockerAdapter{}).Execute(context.Background(), p)
	require.Error(t, err)

	matches, _ := filepath.Glob(filepath.Join(tmp, "dispatcher-env-*.env"))
	assert.Empty(t, matches, "the plaintext env temp file must be cleaned up on the no-image error path")
}

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

// When `docker inspect` is unavailable (--rm removed the container), FailureDetails
// must fall back to the docker-run client's exit code so an OOM/SIGKILLed
// container (137) still gets a transient classification instead of being lost.
func TestDockerFailureDetails_FallsBackToRunExitCode(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 137")
	_ = cmd.Run() // populates ProcessState with exit 137
	h := &RunHandle{ID: "dispatcher-no-such-container-xyz", State: &dockerState{cmd: cmd}}
	fd := (&DockerAdapter{}).FailureDetails(h)
	assert.Equal(t, 137, fd.ExitCode, "inspect unavailable → use the docker-run exit code")
	assert.Equal(t, FailureTransient, ClassifyFailure(fd), "137 is a SIGKILL → transient (retryable)")
}
