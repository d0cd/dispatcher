package cost

import (
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryStore_RecordAndEstimate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	store, err := NewHistoryStore()
	require.NoError(t, err)
	assert.Equal(t, 0, store.Len())

	// Record some runs
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Record(RunHistory{
			RunID:          "run_" + string(rune('a'+i)),
			TargetID:       "local-process",
			WorkloadKind:   "script",
			ActualDuration: 30 * time.Second,
			EstimatedCost:  0.0,
			ActualCost:     0.0,
			Success:        true,
			CompletedAt:    time.Now(),
		}))
	}

	assert.Equal(t, 5, store.Len())

	// Estimate duration should return median
	dur := store.EstimateDuration("local-process", "script")
	assert.Equal(t, 30*time.Second, dur)
}

func TestHistoryStore_EstimateDuration_NoData(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	store, err := NewHistoryStore()
	require.NoError(t, err)

	dur := store.EstimateDuration("unknown-target", "script")
	assert.Equal(t, time.Duration(0), dur)
}

func TestHistoryStore_EstimateDuration_MedianNotAverage(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	store, err := NewHistoryStore()
	require.NoError(t, err)

	// Record durations: 10s, 20s, 30s, 100s, 200s
	durations := []time.Duration{10 * time.Second, 20 * time.Second, 30 * time.Second, 100 * time.Second, 200 * time.Second}
	for i, d := range durations {
		require.NoError(t, store.Record(RunHistory{
			RunID:          "run_" + string(rune('a'+i)),
			TargetID:       "k8s",
			WorkloadKind:   "job",
			ActualDuration: d,
			Success:        true,
		}))
	}

	// Median of [10, 20, 30, 100, 200] = 30
	dur := store.EstimateDuration("k8s", "job")
	assert.Equal(t, 30*time.Second, dur)
}

func TestHistoryStore_ConfidenceForTarget(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	store, err := NewHistoryStore()
	require.NoError(t, err)

	// Not enough data
	conf := store.ConfidenceForTarget("local-process")
	assert.Empty(t, conf)

	// Record accurate estimates
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Record(RunHistory{
			TargetID:      "local-process",
			EstimatedCost: 1.00,
			ActualCost:    1.05, // 5% error
			Success:       true,
		}))
	}

	conf = store.ConfidenceForTarget("local-process")
	assert.Equal(t, types.ConfidenceHigh, conf)
}

func TestHistoryStore_ConfidenceForTarget_LowAccuracy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	store, err := NewHistoryStore()
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		require.NoError(t, store.Record(RunHistory{
			TargetID:      "aws-vm",
			EstimatedCost: 1.00,
			ActualCost:    2.50, // 150% error
			Success:       true,
		}))
	}

	conf := store.ConfidenceForTarget("aws-vm")
	assert.Equal(t, types.ConfidenceLow, conf)
}

func TestHistoryStore_SkipsFailedRuns(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	store, err := NewHistoryStore()
	require.NoError(t, err)

	// Record a failed run with outlier duration
	require.NoError(t, store.Record(RunHistory{
		TargetID:       "local-process",
		WorkloadKind:   "script",
		ActualDuration: 999 * time.Hour, // outlier
		Success:        false,
	}))

	// Record a successful run
	require.NoError(t, store.Record(RunHistory{
		TargetID:       "local-process",
		WorkloadKind:   "script",
		ActualDuration: 5 * time.Second,
		Success:        true,
	}))

	dur := store.EstimateDuration("local-process", "script")
	assert.Equal(t, 5*time.Second, dur) // failed run excluded
}

func TestHistoryStore_Persistence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Write
	store1, err := NewHistoryStore()
	require.NoError(t, err)
	require.NoError(t, store1.Record(RunHistory{
		RunID:    "run_persist",
		TargetID: "local-process",
		Success:  true,
	}))

	// Reload
	store2, err := NewHistoryStore()
	require.NoError(t, err)
	assert.Equal(t, 1, store2.Len())
}

func TestHistoryStore_MaxEntries(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	store, err := NewHistoryStore()
	require.NoError(t, err)

	for i := 0; i < 600; i++ {
		require.NoError(t, store.Record(RunHistory{
			RunID:    "run_" + string(rune(i)),
			TargetID: "test",
			Success:  true,
		}))
	}

	assert.LessOrEqual(t, store.Len(), 500)
}

func TestHistoryStore_Stats(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	store, err := NewHistoryStore()
	require.NoError(t, err)

	require.NoError(t, store.Record(RunHistory{
		TargetID:       "local-process",
		ActualDuration: 10 * time.Second,
		ActualCost:     0,
		Success:        true,
	}))
	require.NoError(t, store.Record(RunHistory{
		TargetID:       "local-process",
		ActualDuration: 20 * time.Second,
		ActualCost:     0,
		Success:        true,
	}))
	require.NoError(t, store.Record(RunHistory{
		TargetID: "local-process",
		Success:  false,
	}))

	stats := store.Stats("local-process")
	assert.Equal(t, 3, stats.TotalRuns)
	assert.Equal(t, 2, stats.SuccessRuns)
	assert.Equal(t, 15*time.Second, stats.AvgDuration)
}

func TestEstimateCostWithHistory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	store, err := NewHistoryStore()
	require.NoError(t, err)

	// Record some historical runs with 30-minute durations
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Record(RunHistory{
			TargetID:       "kubernetes",
			WorkloadKind:   "job",
			ActualDuration: 30 * time.Minute,
			EstimatedCost:  2.0,
			ActualCost:     1.0,
			Success:        true,
		}))
	}

	w := types.WorkloadSpec{
		DetectedKind: types.WorkloadKindJob,
		Requirements: types.ResourceRequirements{CPU: "2"},
	}
	target := types.TargetConfig{
		ID: "kubernetes",
		Capabilities: types.Capabilities{
			Accounting: types.AccountingCapability{RateCard: "internal"},
		},
	}

	// With history: should use 30min instead of default 1h
	withHistory := EstimateCostWithHistory(w, target, store)
	assert.Contains(t, withHistory.Assumptions[0], "historical")

	// Without history: uses default 1h
	withoutHistory := EstimateCost(w, target)

	// Historical estimate should be cheaper (30min vs 1h)
	assert.Less(t, withHistory.Value, withoutHistory.Value)
}
