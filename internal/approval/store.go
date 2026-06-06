// Package approval persists policy approvals per run so a fresh CLI process
// (or different operator) can see what was decided and when.
package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// Decision is the resolution of a pending approval.
type Decision string

const (
	DecisionPending  Decision = "pending"
	DecisionApproved Decision = "approved"
	DecisionDenied   Decision = "denied"
)

// Record is the on-disk shape of an approval request and its resolution.
type Record struct {
	RunID        string                    `json:"runId"`
	Requirements []types.PolicyRequirement `json:"requirements"`
	RequestedAt  time.Time                 `json:"requestedAt"`
	DecidedAt    time.Time                 `json:"decidedAt,omitempty"`
	Decision     Decision                  `json:"decision"`
	Decider      string                    `json:"decider,omitempty"`
}

// RequestPending creates a pending record. Returns the on-disk path.
func RequestPending(runID string, reqs []types.PolicyRequirement) (Record, string, error) {
	r := Record{
		RunID:        runID,
		Requirements: reqs,
		RequestedAt:  time.Now().UTC(),
		Decision:     DecisionPending,
	}
	path, err := write(r)
	return r, path, err
}

// Resolve marks an existing record as approved or denied.
func Resolve(runID string, decision Decision, decider string) (Record, error) {
	rec, err := Load(runID)
	if err != nil {
		return Record{}, err
	}
	if rec.Decision != DecisionPending {
		return rec, fmt.Errorf("approval for %s already resolved: %s", runID, rec.Decision)
	}
	rec.Decision = decision
	rec.DecidedAt = time.Now().UTC()
	rec.Decider = decider
	_, err = write(rec)
	return rec, err
}

// Load reads an existing approval record.
func Load(runID string) (Record, error) {
	dir, err := state.Subdir("approvals")
	if err != nil {
		return Record{}, err
	}
	data, err := os.ReadFile(filepath.Join(dir, runID+".json"))
	if err != nil {
		return Record{}, fmt.Errorf("approval for %s: %w", runID, err)
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return Record{}, fmt.Errorf("parse approval: %w", err)
	}
	return r, nil
}

// ListPending returns all records still in the pending state, oldest first.
func ListPending() ([]Record, error) {
	dir, err := state.Subdir("approvals")
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var pending []Record
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var r Record
		if err := json.Unmarshal(data, &r); err != nil {
			continue
		}
		if r.Decision == DecisionPending {
			pending = append(pending, r)
		}
	}
	return pending, nil
}

func write(r Record) (string, error) {
	dir, err := state.Subdir("approvals")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, r.RunID+".json")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write approval %s: %w", path, err)
	}
	return path, nil
}
