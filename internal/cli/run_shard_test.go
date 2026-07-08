package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/shard"
	"github.com/d0cd/dispatcher/internal/types"
)

func shardPlan(spec types.ShardSpec) *types.Plan {
	return &types.Plan{
		Metadata:       types.PlanMetadata{ID: "plan_shard"},
		Recommendation: &types.Recommendation{Target: "local-process"},
		Workload:       types.WorkloadSpec{Name: "app", Shard: spec},
	}
}

func TestRunSharded_CountMode(t *testing.T) {
	var ran int32
	var indices sync.Map
	err := runSharded(context.Background(), shardPlan(types.ShardSpec{Count: 4}),
		func(_ context.Context, a shard.Assignment) error {
			atomic.AddInt32(&ran, 1)
			indices.Store(a.Index, a.Count)
			return nil
		})
	require.NoError(t, err)
	assert.Equal(t, int32(4), ran)
	for i := 0; i < 4; i++ {
		c, ok := indices.Load(i)
		require.True(t, ok, "shard %d ran", i)
		assert.Equal(t, 4, c)
	}
}

func TestRunSharded_FailureFailsTheRun(t *testing.T) {
	err := runSharded(context.Background(), shardPlan(types.ShardSpec{Count: 3, OnShardFailure: "continue"}),
		func(_ context.Context, a shard.Assignment) error {
			if a.Index == 1 {
				return fmt.Errorf("boom")
			}
			return nil
		})
	require.Error(t, err, "a failed shard fails the overall sharded run")
	assert.Contains(t, err.Error(), "shard")

	// A shard's workload failure is a workload-level failure — exit 3, matching
	// the single-run path (not the generic exit 1).
	var ee *ExitError
	require.True(t, errors.As(err, &ee), "sharded failure carries an exit code")
	assert.Equal(t, 3, ee.Code)
}

func TestRunSharded_NoShardsIsAnError(t *testing.T) {
	err := runSharded(context.Background(), shardPlan(types.ShardSpec{Count: 0}),
		func(context.Context, shard.Assignment) error { return nil })
	require.Error(t, err, "a shard config that yields nothing must fail loudly, not silently no-op")
}

func TestRunSharded_DiscoverRejectsNonLocalTarget(t *testing.T) {
	p := shardPlan(types.ShardSpec{Discover: "ls", Count: 2})
	p.Recommendation.Target = "aws-vm"
	err := runSharded(context.Background(), p, func(context.Context, shard.Assignment) error { return nil })
	require.Error(t, err, "discover-mode item files are host-local; non-local targets can't read them yet")
	assert.Contains(t, err.Error(), "local-process")
}

func TestShardOutcomes_ArtifactDirs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	o := newShardOutcomes()
	o.record(0, &run.Run{ID: "run_a", Artifacts: []adapter.ArtifactRef{{Name: "x", Path: "/p"}}})
	o.record(1, &run.Run{ID: "run_b"}) // ran, produced no artifacts
	o.record(2, nil)                   // never ran (skipped)

	dirs := o.artifactDirs()
	require.Len(t, dirs, 1, "only a shard that produced artifacts contributes a dir")
	assert.Contains(t, dirs[0], "run_a")
	assert.Contains(t, dirs[0], "artifacts")
}

func TestAggregateShardArtifacts_SymlinksEachShard(t *testing.T) {
	// Two fake shard artifact dirs, each with an output file.
	shard0 := filepath.Join(t.TempDir(), "run0", "artifacts")
	shard1 := filepath.Join(t.TempDir(), "run1", "artifacts")
	for i, d := range []string{shard0, shard1} {
		require.NoError(t, os.MkdirAll(d, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(d, "result.txt"), []byte{byte('0' + i)}, 0o600))
	}

	dest := filepath.Join(t.TempDir(), "agg")
	n, err := aggregateShardArtifacts(dest, map[int]string{0: shard0, 1: shard1})
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	// Each shard is reachable via dest/shard-<i>/result.txt through the symlink.
	for i := range []int{0, 1} {
		body, err := os.ReadFile(filepath.Join(dest, fmt.Sprintf("shard-%d", i), "result.txt"))
		require.NoError(t, err, "shard-%d output is reachable through the aggregate", i)
		assert.Equal(t, []byte{byte('0' + i)}, body)
	}
}

func TestAggregateShardArtifacts_NoArtifactsIsNoOp(t *testing.T) {
	n, err := aggregateShardArtifacts(filepath.Join(t.TempDir(), "agg"), nil)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "local runs keep outputs in-place; nothing to aggregate")
}

func TestClonePlanForShard_SetsEnvWithoutMutatingBase(t *testing.T) {
	base := shardPlan(types.ShardSpec{Count: 2})
	base.Workload.Env = map[string]string{"BASE": "1"}

	p := clonePlanForShard(base, shard.Assignment{Index: 2, Count: 5})
	assert.Equal(t, "2", p.Workload.Env["SHARD_INDEX"])
	assert.Equal(t, "5", p.Workload.Env["SHARD_COUNT"])
	assert.Equal(t, "1", p.Workload.Env["BASE"], "base env is carried forward")

	_, mutated := base.Workload.Env["SHARD_INDEX"]
	assert.False(t, mutated, "the base plan's env must not be mutated by a shard clone")
}
