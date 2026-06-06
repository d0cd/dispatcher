package plan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// StoreDir returns the directory where plans are persisted.
func StoreDir() (string, error) {
	return state.Subdir("plans")
}

// Save persists a plan to the local store as JSON.
func Save(p *types.Plan) (string, error) {
	dir, err := StoreDir()
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", fmt.Errorf("cannot marshal plan: %w", err)
	}

	path := filepath.Join(dir, p.Metadata.ID+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("cannot write plan: %w", err)
	}

	return path, nil
}

// Load reads a plan from the local store by ID.
func Load(id string) (*types.Plan, error) {
	dir, err := StoreDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("plan %q not found: %w", id, err)
	}

	var p types.Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("cannot parse plan: %w", err)
	}

	return &p, nil
}

// ListSaved returns IDs of all saved plans.
func ListSaved() ([]string, error) {
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
