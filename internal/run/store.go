package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/approval"
	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// RunRecord is the JSON-serializable form of a run.
type RunRecord struct {
	ID         string             `json:"id"`
	PlanID     string             `json:"planId"`
	TargetID   string             `json:"targetId"`
	Owner      string             `json:"owner"`
	State      types.RunState     `json:"state"`
	StartedAt  time.Time          `json:"startedAt,omitempty"`
	FinishedAt time.Time          `json:"finishedAt,omitempty"`
	Error      string             `json:"error,omitempty"`
	Cost       types.CostEstimate `json:"cost"`

	// Failure detail surfaced by the adapter when the run ended in
	// ExecutionFailed. Used by `dispatcher diagnose` to classify the cause
	// (OOM, signal, exit code) without re-running anything.
	Failure    adapter.FailureDetails `json:"failure,omitempty"`
	RetryCount int                    `json:"retryCount,omitempty"`

	// Timeline records the entry time of each phase, for `dispatcher trace`.
	Timeline []PhaseMark `json:"timeline,omitempty"`

	// Durable execution fields
	HandleID      string          `json:"handleId,omitempty"`
	HandleState   json.RawMessage `json:"handleState,omitempty"`
	Lifecycle     LifecycleMode   `json:"lifecycle,omitempty"`
	WatchdogTTL   time.Duration   `json:"watchdogTtl,omitempty"`
	LastHeartbeat time.Time       `json:"lastHeartbeat,omitempty"`
	LogFile       string          `json:"logFile,omitempty"`

	Approval *approval.Record `json:"approval,omitempty"`
}

// ToRecord converts a Run to a serializable RunRecord.
func (r *Run) ToRecord() RunRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return RunRecord{
		ID:            r.ID,
		PlanID:        r.PlanID,
		TargetID:      r.TargetID,
		Owner:         r.Owner,
		State:         r.State,
		StartedAt:     r.StartedAt,
		FinishedAt:    r.FinishedAt,
		Error:         r.Error,
		Cost:          r.Cost,
		Failure:       r.Failure,
		RetryCount:    r.RetryCount,
		Timeline:      r.Timeline,
		HandleID:      r.HandleID,
		HandleState:   r.HandleState,
		Lifecycle:     r.Lifecycle,
		WatchdogTTL:   r.WatchdogTTL,
		LastHeartbeat: r.LastHeartbeat,
		LogFile:       r.LogFile,
		Approval:      r.Approval,
	}
}

func StoreDir() (string, error) {
	return state.Subdir("runs")
}

func (r *Run) Save() (string, error) {
	if err := validateRunID(r.ID); err != nil {
		return "", err
	}
	dir, err := StoreDir()
	if err != nil {
		return "", err
	}

	record := r.ToRecord()
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", fmt.Errorf("cannot marshal run: %w", err)
	}

	path := filepath.Join(dir, r.ID+".json")
	if err := atomicWriteLocked(path, data, 0o600); err != nil {
		return "", fmt.Errorf("cannot write run: %w", err)
	}

	return path, nil
}

// atomicWriteLocked: flock + write-tmp-then-rename. Concurrent readers
// see either the prior version or the new one, never a torn write.
func atomicWriteLocked(path string, data []byte, perm os.FileMode) error {
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock %s: %w", lockPath, err)
	}
	// Do NOT unlink the lock file: removing it while holding the flock lets a
	// second process os.OpenFile a fresh inode at the same path and flock that, so
	// two writers would both believe they hold the lock. Keeping a stable lock file
	// is what makes the flock actually mutually exclusive; it is one-per-run-state-
	// file and reaped with the run dir.
	defer lock.Close()
	if err := flockExclusive(lock); err != nil {
		return fmt.Errorf("acquire lock %s: %w", lockPath, err)
	}
	defer flockUnlock(lock)

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

var planIDPattern = regexp.MustCompile(`"planId"\s*:\s*"([^"]+)"`)

// RecoverPlanID returns the plan id a run record references even when the record
// can't be fully parsed (truncated/corrupt), so gc can still protect the run's
// (possibly live) cloud resources — VMs are tagged with the plan id, not the run
// id. Returns "" only if the plan id can't be recovered at all.
func RecoverPlanID(id string) string {
	if err := validateRunID(id); err != nil {
		return ""
	}
	dir, err := StoreDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		return ""
	}
	// Common case: a schema/field error, not truncation — a strict parse of just
	// the plan id still works.
	var rec struct {
		PlanID string `json:"planId"`
	}
	if json.Unmarshal(data, &rec) == nil && rec.PlanID != "" {
		return rec.PlanID
	}
	// Truncated/invalid JSON: recover the plan id lexically.
	if m := planIDPattern.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

func LoadRecord(id string) (*RunRecord, error) {
	if err := validateRunID(id); err != nil {
		return nil, err
	}
	dir, err := StoreDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("run %q not found — run `dispatcher list` to see available runs", id)
		}
		return nil, fmt.Errorf("cannot read run %q: %w", id, err)
	}

	var record RunRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("cannot parse run: %w", err)
	}

	return &record, nil
}

func validateRunID(id string) error {
	if id == "" {
		return fmt.Errorf("run id is empty")
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid run id %q: contains path separator or traversal", id)
	}
	return nil
}

func ListRecords() ([]string, error) {
	dir, err := StoreDir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			ids = append(ids, e.Name()[:len(e.Name())-5])
		}
	}
	return ids, nil
}
