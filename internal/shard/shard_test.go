package shard

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

func TestPlan_CountMode(t *testing.T) {
	got := Plan(types.ShardSpec{Count: 3}, nil)
	require.Len(t, got, 3)
	for i, a := range got {
		assert.Equal(t, i, a.Index)
		assert.Equal(t, 3, a.Count)
		assert.Empty(t, a.Items, "count mode carries no items; each shard partitions its own work")
	}
}

func TestPlan_CountZeroOrNegative(t *testing.T) {
	assert.Nil(t, Plan(types.ShardSpec{Count: 0}, nil))
	assert.Nil(t, Plan(types.ShardSpec{Count: -1}, nil))
}

func TestPlan_DiscoverMode_DistributesRoundRobin(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	got := Plan(types.ShardSpec{Discover: "ls", Count: 2}, items)
	require.Len(t, got, 2)
	assert.Equal(t, 2, got[0].Count)
	// round-robin: shard0 gets a,c,e ; shard1 gets b,d
	assert.Equal(t, []string{"a", "c", "e"}, got[0].Items)
	assert.Equal(t, []string{"b", "d"}, got[1].Items)

	// Every item lands in exactly one shard.
	total := 0
	for _, a := range got {
		total += len(a.Items)
	}
	assert.Equal(t, len(items), total)
}

func TestPlan_DiscoverMode_DefaultsToOneShardPerItem(t *testing.T) {
	got := Plan(types.ShardSpec{Discover: "ls"}, []string{"x", "y", "z"})
	require.Len(t, got, 3, "no count → one shard per work item")
	for _, a := range got {
		assert.Len(t, a.Items, 1)
	}
}

func TestPlan_DiscoverMode_CountCappedToItemCount(t *testing.T) {
	got := Plan(types.ShardSpec{Discover: "ls", Count: 10}, []string{"x", "y"})
	assert.Len(t, got, 2, "never create empty shards beyond the item count")
}

func TestPlan_DiscoverMode_NoItems(t *testing.T) {
	assert.Nil(t, Plan(types.ShardSpec{Discover: "ls"}, nil))
}

func TestAssignment_Env(t *testing.T) {
	env := Assignment{Index: 2, Count: 5}.Env()
	assert.Contains(t, env, "SHARD_INDEX=2")
	assert.Contains(t, env, "SHARD_COUNT=5")
	assert.NotContains(t, strings.Join(env, ","), "SHARD_ITEMS", "no items → no SHARD_ITEMS")

	withItems := Assignment{Index: 0, Count: 2, Items: []string{"test_a", "test_b"}}.Env()
	assert.Contains(t, withItems, "SHARD_ITEMS=test_a\ntest_b")
}

func TestDiscover(t *testing.T) {
	// A discovery command's non-empty, trimmed stdout lines are the work items.
	items, err := Discover(context.Background(), "printf 'a\\n b \\n\\nc\\n'", t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, items, "lines trimmed, blanks dropped")
}

func TestDiscover_CommandFailure(t *testing.T) {
	_, err := Discover(context.Background(), "exit 3", t.TempDir())
	require.Error(t, err)
}
