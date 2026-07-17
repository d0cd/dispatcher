package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/shard"
	"github.com/d0cd/dispatcher/internal/types"
)

// shardOutcomes collects each shard's run so their outputs can be aggregated
// after the fan-out. Safe for concurrent record from shard goroutines.
type shardOutcomes struct {
	mu   sync.Mutex
	runs map[int]*run.Run
}

func newShardOutcomes() *shardOutcomes { return &shardOutcomes{runs: map[int]*run.Run{}} }

func (s *shardOutcomes) record(idx int, r *run.Run) {
	if r == nil {
		return
	}
	s.mu.Lock()
	s.runs[idx] = r
	s.mu.Unlock()
}

// artifactDirs maps shard index → its runs/<id>/artifacts directory, for every
// shard whose run retrieved outputs. Local, SSH, and cloud adapters all copy
// declared outputs there, so any shard with outputs appears here; a shard that
// produced none is omitted.
func (s *shardOutcomes) artifactDirs() map[int]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	dirs := map[int]string{}
	base, err := run.StoreDir()
	if err != nil {
		return dirs
	}
	for idx, r := range s.runs {
		if len(r.Artifacts) == 0 {
			continue
		}
		dirs[idx] = filepath.Join(base, r.ID, "artifacts")
	}
	return dirs
}

// aggregateShardArtifacts symlinks each shard's artifacts directory under
// destRoot as shard-<index>, giving one place to find every shard's outputs
// without copying. Idempotent. Returns how many shards were linked.
func aggregateShardArtifacts(destRoot string, artifactDirs map[int]string) (int, error) {
	if len(artifactDirs) == 0 {
		return 0, nil
	}
	if err := os.MkdirAll(destRoot, 0o700); err != nil {
		return 0, err
	}
	n := 0
	for idx, dir := range artifactDirs {
		link := filepath.Join(destRoot, fmt.Sprintf("shard-%d", idx))
		_ = os.Remove(link)
		if err := os.Symlink(dir, link); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

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
	// Give each shard a distinct identity: cloud provisioning derives the VM name
	// from the workload name and the per-run SSH key path + gc tag from the plan
	// id, so without a per-shard suffix a count-mode cloud fan-out collides (all
	// shards share one VM name and one key path, and shards 2..N fail).
	suffix := fmt.Sprintf("-s%d", a.Index)
	p.Metadata.ID = base.Metadata.ID + suffix
	p.Workload.Name = base.Workload.Name + suffix
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
		// A shard's workload not completing is a workload-level failure (exit 3),
		// mirroring the single-run path's exit codes; the summary above is the
		// user-facing message, so don't reprint.
		return &ExitError{
			Code:           3,
			Err:            fmt.Errorf("sharded run incomplete: %d of %d shards succeeded", summary.Succeeded(), len(assignments)),
			AlreadyPrinted: true,
		}
	}
	return nil
}

// runOneShard executes a single shard as a full dispatcher run, on the plan's
// target, with the shard's identity injected as runtime env. It returns the run
// (even on failure) so its outputs can be aggregated.
func runOneShard(ctx context.Context, base *types.Plan, a shard.Assignment) (*run.Run, error) {
	p := clonePlanForShard(base, a)

	// Discover-mode work items travel by file, not env.
	if len(a.Items) > 0 {
		itemsFile, cleanup, err := shard.WriteItemsFile(a.Items)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		p.Workload.Env["SHARD_ITEMS_FILE"] = itemsFile
	}

	// Route through adapterForPlan (not adapterForTarget) so a confidential
	// shard gets the same attesting backend as a non-sharded confidential run.
	adapter, err := adapterForPlan(ctx, p)
	if err != nil {
		return nil, err
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
	if _, saveErr := r.Save(); saveErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save shard run %s: %v\n", r.ID, saveErr)
	}
	recordRunHistory(r, p)
	return r, err
}
