// Package cost stores run-history data used for cost estimation. Storage
// is JSONL at <state-dir>/history.jsonl; Record uses O_APPEND (atomic
// for sub-PIPE_BUF writes) so concurrent dispatchers never lose entries.
// Compaction runs on load when the file exceeds the cap.
package cost

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// maxEntries is the cap on retained run history. Old entries are trimmed
// when the on-disk file grows past 2x this number.
const maxEntries = 500

// RunHistory records the actual outcome of a completed run.
type RunHistory struct {
	RunID          string        `json:"runId"`
	TargetID       string        `json:"targetId"`
	WorkloadKind   string        `json:"workloadKind"`
	WorkloadName   string        `json:"workloadName"`
	Runtime        string        `json:"runtime"`
	ActualDuration time.Duration `json:"actualDuration"`
	EstimatedCost  float64       `json:"estimatedCost"`
	ActualCost     float64       `json:"actualCost"`
	Confidence     string        `json:"confidence"`
	CompletedAt    time.Time     `json:"completedAt"`
	Success        bool          `json:"success"`
	// FinalState and FailureMessage are populated for failed runs so
	// post-hoc analysis ("why does target X fail so much?") can attribute
	// without re-loading the run record.
	FinalState     string `json:"finalState,omitempty"`
	FailureMessage string `json:"failureMessage,omitempty"`
}

// HistoryStore manages historical run data.
type HistoryStore struct {
	mu      sync.RWMutex
	entries []RunHistory
	path    string
}

// NewHistoryStore creates a store backed by a JSONL file in the state dir.
func NewHistoryStore() (*HistoryStore, error) {
	dir, err := state.Dir()
	if err != nil {
		return nil, err
	}
	store := &HistoryStore{path: filepath.Join(dir, "history.jsonl")}
	store.load()
	return store, nil
}

// Record appends a completed run to the history. Uses O_APPEND so
// concurrent dispatcher processes never lose each other's entries.
//
// The on-disk file is intentionally NOT trimmed here — trimming during
// Record means snapshotting the in-memory state and rewriting the file,
// which races against any other process's concurrent appends (they'd
// land on a soon-to-be-deleted inode). Disk size grows unbounded between
// dispatcher invocations; the next NewHistoryStore call trims on load.
func (h *HistoryStore) Record(entry RunHistory) error {
	// Defensive bound: workload names can theoretically be large; cap the
	// serialized line at 1 KiB so it stays well under PIPE_BUF (4 KiB)
	// and Linux/macOS guarantee O_APPEND atomicity.
	if len(entry.WorkloadName) > 256 {
		entry.WorkloadName = entry.WorkloadName[:256] + "…"
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal history entry: %w", err)
	}
	line = append(line, '\n')
	if len(line) > 4096 {
		// Last-resort truncation. The runID + targetID + numbers fit
		// easily; this guards against pathological future fields.
		return fmt.Errorf("history entry exceeds PIPE_BUF (%d bytes); refusing to risk torn write", len(line))
	}

	// O_APPEND is atomic for writes < PIPE_BUF on both Linux and macOS:
	// two concurrent Record calls produce two complete lines in some
	// interleaved order rather than one mangled line.
	f, err := os.OpenFile(h.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return fmt.Errorf("write history entry: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	h.mu.Lock()
	h.entries = append(h.entries, entry)
	// In-memory cap is strict so estimators never look at more than
	// `maxEntries` worth of data.
	if len(h.entries) > maxEntries {
		h.entries = h.entries[len(h.entries)-maxEntries:]
	}
	h.mu.Unlock()
	return nil
}

// SpendSince sums ActualCost across runs targeting targetID that
// completed at or after `since`. Returns the total and run count.
// Negative per-entry costs (a sign of clock skew or arithmetic bugs
// upstream) are clamped to zero so a single bad entry can't make the
// month look free.
func (h *HistoryStore) SpendSince(targetID string, since time.Time) (total float64, runs int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, e := range h.entries {
		if e.TargetID != targetID {
			continue
		}
		if e.CompletedAt.Before(since) {
			continue
		}
		c := e.ActualCost
		if c < 0 {
			c = 0
		}
		total += c
		runs++
	}
	return total, runs
}

// EstimateDuration returns the average duration for similar runs.
// Returns 0 if no historical data is available.
func (h *HistoryStore) EstimateDuration(targetID, workloadKind string) time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var durations []time.Duration
	for _, e := range h.entries {
		if !e.Success {
			continue
		}
		if e.TargetID == targetID && e.WorkloadKind == workloadKind {
			durations = append(durations, e.ActualDuration)
		}
	}

	if len(durations) == 0 {
		return 0
	}

	return median(durations)
}

// ConfidenceForTarget returns improved confidence based on historical accuracy.
func (h *HistoryStore) ConfidenceForTarget(targetID string) types.Confidence {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var errors []float64
	for _, e := range h.entries {
		if e.TargetID != targetID || !e.Success || e.EstimatedCost == 0 {
			continue
		}
		pctErr := math.Abs(e.ActualCost-e.EstimatedCost) / e.EstimatedCost
		errors = append(errors, pctErr)
	}

	if len(errors) < 3 {
		return ""
	}

	avgErr := avg(errors)
	if avgErr < 0.15 {
		return types.ConfidenceHigh
	}
	if avgErr < 0.40 {
		return types.ConfidenceMedium
	}
	return types.ConfidenceLow
}

// Stats returns summary statistics for a target.
func (h *HistoryStore) Stats(targetID string) TargetStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var stats TargetStats
	for _, e := range h.entries {
		if e.TargetID != targetID {
			continue
		}
		stats.TotalRuns++
		if e.Success {
			stats.SuccessRuns++
			stats.TotalCost += e.ActualCost
			stats.TotalDuration += e.ActualDuration
		}
	}
	if stats.SuccessRuns > 0 {
		stats.AvgCost = stats.TotalCost / float64(stats.SuccessRuns)
		stats.AvgDuration = stats.TotalDuration / time.Duration(stats.SuccessRuns)
	}
	return stats
}

// AllStats returns stats for all targets with history.
func (h *HistoryStore) AllStats() map[string]TargetStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	targets := map[string]bool{}
	for _, e := range h.entries {
		targets[e.TargetID] = true
	}

	result := make(map[string]TargetStats, len(targets))
	for t := range targets {
		result[t] = h.Stats(t)
	}
	return result
}

// Len returns the number of history entries.
func (h *HistoryStore) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.entries)
}

// TargetStats summarizes historical run data for a target.
type TargetStats struct {
	TotalRuns     int           `json:"totalRuns"`
	SuccessRuns   int           `json:"successRuns"`
	TotalCost     float64       `json:"totalCost"`
	AvgCost       float64       `json:"avgCost"`
	TotalDuration time.Duration `json:"totalDuration"`
	AvgDuration   time.Duration `json:"avgDuration"`
}

// load reads the JSONL file into memory. Malformed lines are skipped (one
// bad line shouldn't corrupt the whole history). If the on-disk file has
// grown well past the cap, the file is compacted on load — this is the
// only place trimming happens, so concurrent Record calls can never race
// the rewrite (Record only appends, never rewrites).
func (h *HistoryStore) load() {
	f, err := os.Open(h.path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	// Allow larger lines than the default 64 KiB — a history entry with
	// long workload names could exceed it.
	scanner.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry RunHistory
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		h.entries = append(h.entries, entry)
	}
	// Trim to the last maxEntries on load — older entries are still on
	// disk but we don't care about them for estimation.
	if len(h.entries) > maxEntries {
		h.entries = h.entries[len(h.entries)-maxEntries:]
	}
	// Compact when the file has grown past 4x the cap. Doing it here
	// (in NewHistoryStore, called once per CLI invocation) is safe:
	// nothing else is using the file yet. If two CLI processes start
	// simultaneously both may try to trim; we serialize with a flock-
	// style lock file so only one rewrite wins.
	if info, err := os.Stat(h.path); err == nil && info.Size() > int64(4*maxEntries*400) {
		_ = h.compactOnLoad()
	}
}

// compactOnLoad atomically rewrites the file to contain just the
// in-memory entries (already capped at maxEntries). Uses temp+rename so
// concurrent O_APPEND writers from another CLI invocation might land in
// the old inode and lose their write — to avoid this, we acquire an
// exclusive flock on a sibling .lock file, blocking any other CLI's
// compactOnLoad until we finish. Record() doesn't take this lock; it
// only appends, which is atomic regardless.
func (h *HistoryStore) compactOnLoad() error {
	lockPath := h.path + ".compact.lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	defer os.Remove(lockPath)
	if err := flockExclusive(lock); err != nil {
		return err
	}
	defer flockUnlock(lock)

	tmp := h.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	for _, e := range h.entries {
		line, err := json.Marshal(e)
		if err != nil {
			f.Close()
			_ = os.Remove(tmp)
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			f.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, h.path)
}

func median(ds []time.Duration) time.Duration {
	n := len(ds)
	if n == 0 {
		return 0
	}
	sorted := make([]time.Duration, n)
	copy(sorted, ds)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	return sorted[n/2]
}

func avg(vs []float64) float64 {
	if len(vs) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vs {
		sum += v
	}
	return sum / float64(len(vs))
}
