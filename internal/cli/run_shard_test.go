package cli

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
}

func TestRunSharded_NoShardsIsAnError(t *testing.T) {
	err := runSharded(context.Background(), shardPlan(types.ShardSpec{Count: 0}),
		func(context.Context, shard.Assignment) error { return nil })
	require.Error(t, err, "a shard config that yields nothing must fail loudly, not silently no-op")
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
