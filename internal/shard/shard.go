// Package shard fans one workload out across many runs: it computes the shard
// assignments (this file) and, in the engine, runs them and aggregates outputs.
package shard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/d0cd/dispatcher/internal/types"
)

// Assignment is one shard's slice of the work.
type Assignment struct {
	Index int      // 0..Count-1, exported to the shard as SHARD_INDEX
	Count int      // total shard count, exported as SHARD_COUNT
	Items []string // work items for this shard (discover mode); nil in count mode
}

// Env is the shard's identity as environment entries: SHARD_INDEX and
// SHARD_COUNT. Discover-mode work items are NOT passed here — newline-joined
// values corrupt docker `--env-file` / SSH heredocs, so items are delivered via
// a file (SHARD_ITEMS_FILE) by the runner instead.
func (a Assignment) Env() map[string]string {
	return map[string]string{
		"SHARD_INDEX": fmt.Sprintf("%d", a.Index),
		"SHARD_COUNT": fmt.Sprintf("%d", a.Count),
	}
}

// WriteItemsFile writes a shard's work items (one per line) to a 0600 temp file,
// returning its path and a cleanup func. Items travel by file (SHARD_ITEMS_FILE),
// not env, because they may contain spaces/newlines that would corrupt an
// --env-file. os.CreateTemp already creates the file mode 0600.
func WriteItemsFile(items []string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "dispatcher-shard-items-*.txt")
	if err != nil {
		return "", func() {}, fmt.Errorf("write shard items file: %w", err)
	}
	for _, item := range items {
		if _, err := fmt.Fprintln(f, item); err != nil {
			f.Close()
			_ = os.Remove(f.Name())
			return "", func() {}, err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", func() {}, err
	}
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}

// Discover runs the discovery command in dir and returns its work items — the
// non-empty, trimmed lines of stdout.
func Discover(ctx context.Context, command, dir string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("shard discovery command failed: %w", err)
	}
	var items []string
	for _, line := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			items = append(items, s)
		}
	}
	return items, nil
}

// Plan computes the shard assignments for a spec. In count mode (no Discover) it
// returns Count shards, each partitioning its own work by SHARD_INDEX/SHARD_COUNT.
// In discover mode it distributes the already-discovered items round-robin across
// the shards (Count caps the fan-out; default is one shard per item). Returns nil
// when nothing to shard.
func Plan(spec types.ShardSpec, discovered []string) []Assignment {
	if spec.Discover == "" {
		n := spec.Count
		if n <= 0 {
			return nil
		}
		out := make([]Assignment, n)
		for i := range out {
			out[i] = Assignment{Index: i, Count: n}
		}
		return out
	}

	if len(discovered) == 0 {
		return nil
	}
	n := spec.Count
	if n <= 0 || n > len(discovered) {
		n = len(discovered) // never create empty shards
	}
	out := make([]Assignment, n)
	for i := range out {
		out[i].Index = i
		out[i].Count = n
	}
	for j, item := range discovered {
		out[j%n].Items = append(out[j%n].Items, item)
	}
	return out
}
