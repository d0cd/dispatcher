// Package cost stores run-history data used for cost estimation. Storage
// is JSONL at <state-dir>/history.jsonl; Record uses O_APPEND (atomic
// for sub-PIPE_BUF writes) so concurrent dispatchers never lose entries.
// Compaction runs on load when the file exceeds the cap.
package cost

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// maxEntries is the cap on retained run history. The on-disk file is compacted
// on load once its size exceeds ~4*maxEntries*400 bytes (see load()).
const maxEntries = 500

// maxWorkloadNameBytes bounds the stored workload name so a history line stays
// well under PIPE_BUF; longer names are rune-truncated and hash-suffixed.
const maxWorkloadNameBytes = 256

// truncateToRuneBoundary returns the longest prefix of s that is at most
// maxBytes long and does not end in the middle of a UTF-8 rune.
func truncateToRuneBoundary(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

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
	// and Linux/macOS guarantee O_APPEND atomicity. Truncate on a rune
	// boundary (never leave a partial rune that json.Marshal would corrupt to
	// U+FFFD) and append a short hash of the full name so two distinct long
	// names sharing a prefix don't collapse into one Flakiness signal.
	if len(entry.WorkloadName) > maxWorkloadNameBytes {
		sum := sha256.Sum256([]byte(entry.WorkloadName))
		prefix := truncateToRuneBoundary(entry.WorkloadName, maxWorkloadNameBytes)
		entry.WorkloadName = prefix + "…" + hex.EncodeToString(sum[:4])
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

	// Append under the same flock compactOnLoad uses, so a concurrent CLI's
	// compaction (which renames a fresh file over h.path) can't unlink the inode
	// out from under this append and silently discard it. O_APPEND alone is atomic
	// for writes < PIPE_BUF but does not guard against that rename race. The lock is
	// taken in a self-contained scope (not around compactOnLoad below) so the two
	// never nest into a same-process flock deadlock.
	if err := h.appendLine(line); err != nil {
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

// EstimateDuration returns the median duration for similar runs.
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

// StabilityReport summarizes a workload's recent stability on a target.
type StabilityReport struct {
	Runs     int  `json:"runs"`
	Failures int  `json:"failures"`
	Flaky    bool `json:"flaky"`
}

// Flakiness reports whether a workload has been unstable on a target: among its
// retained runs, both successes and failures appear. A workload that always
// passes — or always fails — is not flaky; a consistent failure is a different
// signal (broken, not flaky). Needs at least two runs to have a basis.
func (h *HistoryStore) Flakiness(workloadName, targetID string) StabilityReport {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var rep StabilityReport
	var successes int
	for _, e := range h.entries {
		if e.WorkloadName != workloadName || e.TargetID != targetID {
			continue
		}
		rep.Runs++
		if e.Success {
			successes++
		} else {
			rep.Failures++
		}
	}
	rep.Flaky = rep.Runs >= 2 && successes > 0 && rep.Failures > 0
	return rep
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
// grown well past the cap, it is compacted on load; the compaction re-reads
// the file under an flock so a Record another process appended concurrently is
// not lost (this is best-effort estimation data — a Record that lands during
// the rewrite itself is a rare, tolerated loss).
// scanHistoryFile reads the JSONL history into a slice, skipping malformed lines
// (one bad line shouldn't corrupt the whole history).
func scanHistoryFile(path string) []RunHistory {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []RunHistory
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
		out = append(out, entry)
	}
	return out
}

func (h *HistoryStore) load() {
	h.entries = scanHistoryFile(h.path)
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

// appendLine appends one framed line to the history file while holding the
// compaction flock, so a concurrent compaction's temp+rename cannot unlink the
// inode out from under the append and discard it.
func (h *HistoryStore) appendLine(line []byte) error {
	lock, err := os.OpenFile(h.path+".compact.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open history lock: %w", err)
	}
	defer lock.Close()
	if err := flockExclusive(lock); err != nil {
		return fmt.Errorf("lock history: %w", err)
	}
	defer flockUnlock(lock)

	f, err := os.OpenFile(h.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return fmt.Errorf("write history entry: %w", err)
	}
	return f.Close()
}

// compactOnLoad atomically rewrites the file to contain just the in-memory
// entries (already capped at maxEntries). Uses temp+rename, so a concurrent
// O_APPEND writer from another CLI could otherwise land in the old inode and lose
// its write; both this and Record's appendLine take the same exclusive flock, so
// the rename and the appends are mutually exclusive. The lock file is kept stable
// (never unlinked) so the flock actually excludes — unlinking it while held lets a
// second process create a fresh inode at the same path and lock that.
func (h *HistoryStore) compactOnLoad() error {
	lockPath := h.path + ".compact.lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := flockExclusive(lock); err != nil {
		return err
	}
	defer flockUnlock(lock)

	// Re-read the file UNDER the lock, not the snapshot load() read before the
	// lock: another process may have appended entries since, and rewriting from
	// the stale snapshot would silently drop them.
	entries := scanHistoryFile(h.path)
	if len(entries) > maxEntries {
		entries = entries[len(entries)-maxEntries:]
	}

	tmp := h.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	for _, e := range entries {
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
	h.entries = entries // keep the in-memory view consistent with the compacted file
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
