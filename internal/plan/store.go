package plan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

func validatePlanID(id string) error {
	if id == "" {
		return fmt.Errorf("plan id is empty")
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid plan id %q: contains path separator or traversal", id)
	}
	return nil
}

func StoreDir() (string, error) {
	return state.Subdir("plans")
}

// Save writes the plan via an atomic temp+rename so concurrent readers
// never see partial JSON.
func Save(p *types.Plan) (string, error) {
	if err := validatePlanID(p.Metadata.ID); err != nil {
		return "", err
	}
	dir, err := StoreDir()
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", fmt.Errorf("cannot marshal plan: %w", err)
	}

	path := filepath.Join(dir, p.Metadata.ID+".json")
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Stale .tmp from a crashed predecessor; reclaim and retry.
			_ = os.Remove(tmp)
			f, err = os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
		}
		if err != nil {
			return "", fmt.Errorf("cannot open plan tempfile: %w", err)
		}
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("cannot write plan: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("cannot install plan: %w", err)
	}

	return path, nil
}

func Load(id string) (*types.Plan, error) {
	if err := validatePlanID(id); err != nil {
		return nil, err
	}
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
