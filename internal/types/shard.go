package types

// ShardSpec declares how to fan one workload out across many runs (from the
// dispatcher.yaml `shard:` / `aggregate:` blocks). Nil/zero means no sharding.
type ShardSpec struct {
	// Count is a fixed shard count. Each shard receives SHARD_INDEX/SHARD_COUNT
	// and partitions its own work. Ignored item-distribution when Discover is set,
	// where it instead caps the number of shards.
	Count int `json:"count,omitempty"`
	// Discover is a command whose stdout lines are the work items; dispatcher
	// distributes them across shards.
	Discover string `json:"discover,omitempty"`
	// MaxParallel bounds how many shards run at once. Zero = an engine default.
	MaxParallel int `json:"maxParallel,omitempty"`
	// Outputs are workload-relative paths collected from each shard and merged.
	Outputs []string `json:"outputs,omitempty"`
	// OnShardFailure is "fail" (default), "retry" (re-run a failed shard once —
	// only safe for idempotent shards), or "continue" (collect partial results).
	OnShardFailure string `json:"onShardFailure,omitempty"`
}

// Enabled reports whether the spec actually requests sharding.
func (s ShardSpec) Enabled() bool {
	return s.Count > 0 || s.Discover != ""
}
