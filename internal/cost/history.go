package cost

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

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
}

// HistoryStore manages historical run data.
type HistoryStore struct {
	mu      sync.RWMutex
	entries []RunHistory
	path    string
}

// NewHistoryStore creates a store backed by a JSON file.
func NewHistoryStore() (*HistoryStore, error) {
	dir, err := state.Dir()
	if err != nil {
		return nil, err
	}
	store := &HistoryStore{path: filepath.Join(dir, "history.json")}
	store.load()
	return store, nil
}

// Record adds a completed run to the history.
func (h *HistoryStore) Record(entry RunHistory) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.entries = append(h.entries, entry)

	// Keep last 500 entries
	if len(h.entries) > 500 {
		h.entries = h.entries[len(h.entries)-500:]
	}

	return h.save()
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

	// Return median duration
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
		return "" // not enough data
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

func (h *HistoryStore) load() {
	data, err := os.ReadFile(h.path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &h.entries)
}

func (h *HistoryStore) save() error {
	data, err := json.MarshalIndent(h.entries, "", "  ")
	if err != nil {
		return err
	}
	// Atomic write via temp file + rename
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.path)
}

func median(ds []time.Duration) time.Duration {
	n := len(ds)
	if n == 0 {
		return 0
	}
	// Simple selection — copy and sort
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
