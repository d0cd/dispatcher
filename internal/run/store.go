package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

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

	// Durable execution fields
	HandleID      string            `json:"handleId,omitempty"`
	HandleState   json.RawMessage   `json:"handleState,omitempty"`
	Lifecycle     LifecycleMode     `json:"lifecycle,omitempty"`
	WatchdogTTL   time.Duration     `json:"watchdogTtl,omitempty"`
	LastHeartbeat time.Time         `json:"lastHeartbeat,omitempty"`
	LogFile       string            `json:"logFile,omitempty"`
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
		HandleID:      r.HandleID,
		HandleState:   r.HandleState,
		Lifecycle:     r.Lifecycle,
		WatchdogTTL:   r.WatchdogTTL,
		LastHeartbeat: r.LastHeartbeat,
		LogFile:       r.LogFile,
	}
}

// StoreDir returns the directory where runs are persisted.
func StoreDir() (string, error) {
	return state.Subdir("runs")
}

// Save persists the run state to disk.
func (r *Run) Save() (string, error) {
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

// atomicWriteLocked writes data to path with an exclusive flock and a
// write-tmp-then-rename sequence so concurrent readers see either the prior
// version or the new one — never a torn write.
func atomicWriteLocked(path string, data []byte, perm os.FileMode) error {
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock %s: %w", lockPath, err)
	}
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

// LoadRecord reads a run record from the store by ID.
func LoadRecord(id string) (*RunRecord, error) {
	dir, err := StoreDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("run %q not found: %w", id, err)
	}

	var record RunRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("cannot parse run: %w", err)
	}

	return &record, nil
}

// ListRecords returns all saved run IDs, most recent first.
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
