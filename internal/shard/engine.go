package shard

import (
	"context"
	"sync"
)

const defaultMaxParallel = 4

// RunFunc executes one shard, returning nil on success. It must honor ctx
// cancellation — fail-fast cancels in-flight shards.
type RunFunc func(ctx context.Context, a Assignment) error

// Result is one shard's outcome. Skipped shards never ran (fail-fast aborted
// before they were launched).
type Result struct {
	Index   int
	Success bool
	Skipped bool
	Err     error
}

// Summary aggregates the shard outcomes.
type Summary struct {
	Results []Result
}

func (s Summary) count(pred func(Result) bool) int {
	n := 0
	for _, r := range s.Results {
		if pred(r) {
			n++
		}
	}
	return n
}

func (s Summary) Succeeded() int { return s.count(func(r Result) bool { return r.Success }) }
func (s Summary) Failed() int {
	return s.count(func(r Result) bool { return !r.Success && !r.Skipped })
}
func (s Summary) Skipped() int { return s.count(func(r Result) bool { return r.Skipped }) }

// OK reports whether every shard succeeded (no failures, none skipped).
func (s Summary) OK() bool { return s.Failed() == 0 && s.Skipped() == 0 }

// Engine runs shard assignments with bounded concurrency and a failure policy.
type Engine struct {
	MaxParallel    int
	OnShardFailure string // "" / "fail" (fail-fast), "retry" (one retry then fail-fast), "continue"
}

// Run executes each assignment via run, bounded by MaxParallel. Under fail/retry
// the first terminal failure cancels the context and stops launching further
// shards; under continue every shard runs and partial results are reported.
func (e Engine) Run(ctx context.Context, assignments []Assignment, run RunFunc) Summary {
	if len(assignments) == 0 {
		return Summary{}
	}

	maxPar := e.MaxParallel
	if maxPar <= 0 {
		maxPar = defaultMaxParallel
	}
	if maxPar > len(assignments) {
		maxPar = len(assignments)
	}
	failFast := e.OnShardFailure != "continue"
	doRetry := e.OnShardFailure == "retry"

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Pre-mark every shard skipped; workers overwrite the ones they run.
	results := make([]Result, len(assignments))
	for i, a := range assignments {
		results[i] = Result{Index: a.Index, Skipped: true}
	}

	runOnce := func(a Assignment) error {
		err := run(ctx, a)
		if err != nil && doRetry && ctx.Err() == nil {
			err = run(ctx, a)
		}
		return err
	}

	type job struct {
		i int
		a Assignment
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for w := 0; w < maxPar; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					continue // aborted: drain remaining without running
				}
				err := runOnce(j.a)
				mu.Lock()
				results[j.i] = Result{Index: j.a.Index, Success: err == nil, Err: err}
				mu.Unlock()
				if err != nil && failFast {
					cancel()
				}
			}
		}()
	}

feed:
	for i, a := range assignments {
		select {
		case <-ctx.Done():
			break feed // stop launching new shards once aborted
		case jobs <- job{i, a}:
		}
	}
	close(jobs)
	wg.Wait()

	return Summary{Results: results}
}
