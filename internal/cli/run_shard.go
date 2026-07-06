package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/shard"
	"github.com/d0cd/dispatcher/internal/types"
)

// clonePlanForShard returns a copy of base with the shard's identity env merged
// into the workload. A fresh Env map is allocated so concurrent shards never
// share or mutate each other's (or the base plan's) environment.
func clonePlanForShard(base *types.Plan, a shard.Assignment) *types.Plan {
	p := *base
	env := make(map[string]string, len(base.Workload.Env)+len(a.Env()))
	for k, v := range base.Workload.Env {
		env[k] = v
	}
	for k, v := range a.Env() {
		env[k] = v
	}
	p.Workload.Env = env
	return &p
}

// runSharded fans a plan out across shards and reports the aggregate outcome.
// The per-shard execution is injected so the discover→plan→schedule flow is
// testable without running real workloads.
func runSharded(ctx context.Context, p *types.Plan, runShard shard.RunFunc) error {
	spec := p.Workload.Shard

	// Discover-mode items are handed to each shard via a host-local file
	// (SHARD_ITEMS_FILE), which only a local target can read. Count mode (just
	// SHARD_INDEX/SHARD_COUNT) works on any target.
	if spec.Discover != "" && p.Recommendation.Target != "local-process" {
		return fmt.Errorf("discover-mode sharding runs on local-process only for now (work items are delivered by a host-local file); count mode works on any target")
	}

	var items []string
	if spec.Discover != "" {
		var err error
		items, err = shard.Discover(ctx, spec.Discover, p.Workload.Source.Path)
		if err != nil {
			return err
		}
	}
	assignments := shard.Plan(spec, items)
	if len(assignments) == 0 {
		return fmt.Errorf("sharding is configured but produced no shards (check shard.count / shard.discover)")
	}

	fmt.Fprintf(os.Stderr, "Fanning out into %d shards on %s...\n", len(assignments), p.Recommendation.Target)

	engine := shard.Engine{MaxParallel: spec.MaxParallel, OnShardFailure: spec.OnShardFailure}
	summary := engine.Run(ctx, assignments, runShard)

	fmt.Fprintf(os.Stderr, "\nShards: %d succeeded, %d failed, %d skipped (of %d)\n",
		summary.Succeeded(), summary.Failed(), summary.Skipped(), len(assignments))
	if !summary.OK() {
		return fmt.Errorf("sharded run incomplete: %d of %d shards succeeded", summary.Succeeded(), len(assignments))
	}
	return nil
}

// runOneShard executes a single shard as a full dispatcher run, on the plan's
// target, with the shard's identity injected as runtime env.
func runOneShard(ctx context.Context, base *types.Plan, a shard.Assignment) error {
	p := clonePlanForShard(base, a)

	// Discover-mode work items travel by file, not env.
	if len(a.Items) > 0 {
		itemsFile, cleanup, err := shard.WriteItemsFile(a.Items)
		if err != nil {
			return err
		}
		defer cleanup()
		p.Workload.Env["SHARD_ITEMS_FILE"] = itemsFile
	}

	adapter, err := adapterForTarget(p.Recommendation.Target)
	if err != nil {
		return err
	}
	r := run.NewRun(p)
	executor := run.NewExecutor(adapter)
	// The fan-out was approved once at the top (runRun gates it), so each shard
	// auto-approves rather than prompting N times.
	executor.SetApprovalFunc(yesApproval)

	logWriter, logCloser := setupRunLogFile(r)
	if logCloser != nil {
		defer logCloser.Close()
	}

	err = executor.Execute(ctx, r, logWriter)
	_, _ = r.Save()
	recordRunHistory(r, p)
	return err
}
