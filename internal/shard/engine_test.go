package shard

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assignments(n int) []Assignment {
	out := make([]Assignment, n)
	for i := range out {
		out[i] = Assignment{Index: i, Count: n}
	}
	return out
}

func TestEngine_AllSucceed(t *testing.T) {
	var ran int32
	sum := Engine{MaxParallel: 3}.Run(context.Background(), assignments(5),
		func(context.Context, Assignment) error { atomic.AddInt32(&ran, 1); return nil })
	assert.Equal(t, int32(5), ran)
	assert.Equal(t, 5, sum.Succeeded())
	assert.Equal(t, 0, sum.Failed())
	assert.True(t, sum.OK())
}

func TestEngine_Continue_RunsAllDespiteFailure(t *testing.T) {
	var ran int32
	sum := Engine{MaxParallel: 2, OnShardFailure: "continue"}.Run(context.Background(), assignments(5),
		func(_ context.Context, a Assignment) error {
			atomic.AddInt32(&ran, 1)
			if a.Index == 1 {
				return fmt.Errorf("boom")
			}
			return nil
		})
	assert.Equal(t, int32(5), ran, "continue runs every shard")
	assert.Equal(t, 4, sum.Succeeded())
	assert.Equal(t, 1, sum.Failed())
	assert.False(t, sum.OK(), "a failed shard means the run isn't clean")
}

func TestEngine_Fail_StopsLaunchingAfterFailure(t *testing.T) {
	var ran int32
	// maxParallel 1 → sequential in index order, so fail-fast is deterministic.
	sum := Engine{MaxParallel: 1, OnShardFailure: "fail"}.Run(context.Background(), assignments(5),
		func(_ context.Context, a Assignment) error {
			atomic.AddInt32(&ran, 1)
			if a.Index == 2 {
				return fmt.Errorf("boom")
			}
			return nil
		})
	assert.Equal(t, int32(3), ran, "shards 0,1,2 ran; 3,4 never launched after the failure")
	assert.Equal(t, 2, sum.Skipped())
	assert.Equal(t, 1, sum.Failed())
}

func TestEngine_Retry_ReRunsFailedShardOnce(t *testing.T) {
	var calls sync.Map // index -> count
	sum := Engine{MaxParallel: 2, OnShardFailure: "retry"}.Run(context.Background(), assignments(3),
		func(_ context.Context, a Assignment) error {
			n, _ := calls.LoadOrStore(a.Index, new(int32))
			c := atomic.AddInt32(n.(*int32), 1)
			if a.Index == 1 && c == 1 {
				return fmt.Errorf("flaky") // fails first attempt, passes on retry
			}
			return nil
		})
	assert.Equal(t, 3, sum.Succeeded(), "the flaky shard passes on its one retry")
	c, _ := calls.Load(1)
	assert.Equal(t, int32(2), atomic.LoadInt32(c.(*int32)), "failed shard was retried exactly once")
}

func TestEngine_RespectsMaxParallel(t *testing.T) {
	var inFlight, peak int32
	Engine{MaxParallel: 3, OnShardFailure: "continue"}.Run(context.Background(), assignments(20),
		func(context.Context, Assignment) error {
			n := atomic.AddInt32(&inFlight, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
					break
				}
			}
			atomic.AddInt32(&inFlight, -1)
			return nil
		})
	assert.LessOrEqual(t, atomic.LoadInt32(&peak), int32(3), "never more than maxParallel shards at once")
}

func TestEngine_NoAssignments(t *testing.T) {
	sum := Engine{}.Run(context.Background(), nil, func(context.Context, Assignment) error {
		require.Fail(t, "runner must not be called with no assignments")
		return nil
	})
	assert.Equal(t, 0, sum.Succeeded())
	assert.True(t, sum.OK())
}
