package target

import (
	"sort"

	"github.com/d0cd/dispatcher/internal/types"
)

// Registry holds configured execution targets.
type Registry struct {
	targets map[string]types.TargetConfig
}

// NewRegistry creates an empty target registry.
func NewRegistry() *Registry {
	return &Registry{targets: make(map[string]types.TargetConfig)}
}

// Add registers a target.
func (r *Registry) Add(t types.TargetConfig) {
	r.targets[t.ID] = t
}

// Get returns a target by ID.
func (r *Registry) Get(id string) (types.TargetConfig, bool) {
	t, ok := r.targets[id]
	return t, ok
}

// List returns all targets in deterministic order.
func (r *Registry) List() []types.TargetConfig {
	// Return in a stable order
	order := []string{"local-process", "local-docker", "lima-vm", "ssh", "kubernetes", "firecracker-vm", "hetzner-vm", "aws-vm", "gcp-vm", "azure-vm"}
	var result []types.TargetConfig
	for _, id := range order {
		if t, ok := r.targets[id]; ok {
			result = append(result, t)
		}
	}
	// Append any targets not in the predefined order, sorted by id so map
	// iteration order can't make List() nondeterministic.
	var extra []string
	for id := range r.targets {
		if !inSlice(order, id) {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	for _, id := range extra {
		result = append(result, r.targets[id])
	}
	return result
}

func inSlice(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// LoadBuiltins registers the built-in target definitions.
func (r *Registry) LoadBuiltins() {
	for _, t := range BuiltinTargets() {
		r.Add(t)
	}
}
