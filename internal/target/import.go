package target

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// managedImportFile is the single file all imported targets are written to, so
// re-import can reconcile them wholesale without touching hand-added targets.
const managedImportFile = "terraform-import.yaml"

// ImportResult summarizes what an import changed, for the CLI to report.
type ImportResult struct {
	Path    string
	Added   []string
	Updated []string
	Removed []string
}

// ImportFromJSON parses a dispatcher_targets blob and reconciles it into the
// managed import file. An empty target list legitimately clears all previously
// imported targets.
func ImportFromJSON(blob []byte) (*ImportResult, error) {
	targets, err := ParseDispatcherTargets(blob)
	if err != nil {
		return nil, err
	}
	return reconcileImport(targets)
}

// reconcileImport rejects collisions with hand-added targets, computes the
// add/update/remove delta against the previous import, and atomically rewrites
// the managed file.
func reconcileImport(targets []types.TargetConfig) (*ImportResult, error) {
	dir, err := state.Subdir("targets")
	if err != nil {
		return nil, err
	}

	// A collision with a hand-added <id>.yaml is resolved by filename sort order
	// at load time, so refuse it outright rather than silently shadow.
	for _, t := range targets {
		if _, err := os.Stat(filepath.Join(dir, t.ID+".yaml")); err == nil {
			return nil, fmt.Errorf("target %q already exists as a hand-added target (%s.yaml); refusing to shadow it", t.ID, t.ID)
		}
	}

	prev := managedIDs(filepath.Join(dir, managedImportFile))
	next := make(map[string]bool, len(targets))
	res := &ImportResult{}
	for _, t := range targets {
		next[t.ID] = true
		if prev[t.ID] {
			res.Updated = append(res.Updated, t.ID)
		} else {
			res.Added = append(res.Added, t.ID)
		}
	}
	for id := range prev {
		if !next[id] {
			res.Removed = append(res.Removed, id)
		}
	}
	sort.Strings(res.Added)
	sort.Strings(res.Updated)
	sort.Strings(res.Removed)

	path, err := WriteTargetsFile(managedImportFile, targets)
	if err != nil {
		return nil, err
	}
	res.Path = path
	return res, nil
}

// managedIDs returns the ids currently in the managed import file (empty if it
// doesn't exist or can't be read — a fresh import).
func managedIDs(path string) map[string]bool {
	m := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	var tf TargetsFile
	if yaml.Unmarshal(data, &tf) == nil {
		for _, t := range tf.Targets {
			m[t.ID] = true
		}
	}
	return m
}

// dispatcherTargetsBlob is the structured contract a source (Terraform output,
// Pulumi, a script) emits to declare importable targets. It maps 1:1 to
// TargetConfig; only SSH targets are importable today.
type dispatcherTargetsBlob struct {
	Targets []importEntry `json:"targets"`
}

type importEntry struct {
	ID   string          `json:"id"`
	Kind string          `json:"kind"`
	SSH  *importSSHEntry `json:"ssh"`
}

type importSSHEntry struct {
	Host    string `json:"host"`
	User    string `json:"user"`
	Port    int    `json:"port"`
	KeyFile string `json:"key_file"`
}

// ParseDispatcherTargets parses a dispatcher_targets blob into validated,
// ready-to-persist TargetConfigs. Every entry is validated at this boundary:
// the id must be safe and not collide with a builtin, the kind must be ssh, and
// the ssh fields must pass ValidateSSHTarget. Imported targets are marked
// Enabled with default capabilities — otherwise the planner drops them as
// infeasible. An empty target list is legitimate (the caller may use it to
// clear previously-imported targets).
func ParseDispatcherTargets(blob []byte) ([]types.TargetConfig, error) {
	var b dispatcherTargetsBlob
	if err := json.Unmarshal(blob, &b); err != nil {
		return nil, fmt.Errorf("parse dispatcher_targets: %w", err)
	}

	reserved := reservedIDs()
	seen := make(map[string]bool, len(b.Targets))
	var out []types.TargetConfig
	for i, e := range b.Targets {
		if err := validateTargetID(e.ID); err != nil {
			return nil, fmt.Errorf("target %d: %w", i, err)
		}
		if reserved[e.ID] {
			return nil, fmt.Errorf("target %q: id collides with a builtin target (reserved)", e.ID)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("duplicate target id %q in dispatcher_targets", e.ID)
		}
		seen[e.ID] = true

		if types.TargetKind(e.Kind) != types.TargetKindSSH {
			return nil, fmt.Errorf("target %q: kind %q is not importable (only ssh today)", e.ID, e.Kind)
		}
		if e.SSH == nil {
			return nil, fmt.Errorf("target %q: missing ssh block", e.ID)
		}
		ssh := &types.SSHTargetConfig{Host: e.SSH.Host, User: e.SSH.User, Port: e.SSH.Port, KeyFile: e.SSH.KeyFile}
		if ssh.Port == 0 {
			ssh.Port = 22
		}
		if err := ValidateSSHTarget(ssh); err != nil {
			return nil, fmt.Errorf("target %q: %w", e.ID, err)
		}

		out = append(out, types.TargetConfig{
			ID:           e.ID,
			Kind:         types.TargetKindSSH,
			Enabled:      true,
			Capabilities: DefaultCapabilities(types.TargetKindSSH),
			SSH:          ssh,
		})
	}
	return out, nil
}

// WriteTargetsFile atomically writes a multi-target TargetsFile under
// <state-dir>/targets/<name>. It re-validates every target (the persist choke
// point), writes to a temp file in the same dir, fsyncs, and renames over the
// destination — so a crash never leaves a half-written managed file. Re-writing
// replaces the file's contents wholesale, which is how re-import reconciles
// add/update/remove.
func WriteTargetsFile(name string, targets []types.TargetConfig) (string, error) {
	for i := range targets {
		if err := validateTargetID(targets[i].ID); err != nil {
			return "", fmt.Errorf("target %d: %w", i, err)
		}
		if targets[i].SSH != nil {
			if err := ValidateSSHTarget(targets[i].SSH); err != nil {
				return "", fmt.Errorf("target %q: %w", targets[i].ID, err)
			}
		}
	}

	dir, err := state.Subdir("targets")
	if err != nil {
		return "", err
	}
	data, err := yaml.Marshal(TargetsFile{Targets: targets})
	if err != nil {
		return "", fmt.Errorf("marshal targets: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-import-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // harmless no-op once the rename succeeds

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	path := filepath.Join(dir, name)
	if err := os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("install %s: %w", name, err)
	}
	return path, nil
}

// reservedIDs is the set of builtin target ids an import must not collide with —
// a builtin-id collision is mis-routed by adapterForTarget, not shadowed.
func reservedIDs() map[string]bool {
	r := NewRegistry()
	r.LoadBuiltins()
	m := make(map[string]bool, len(r.targets))
	for id := range r.targets {
		m[id] = true
	}
	return m
}

// DefaultCapabilities returns sane default capabilities for a target kind, so
// both `targets add` and the importer produce feasible targets.
func DefaultCapabilities(kind types.TargetKind) types.Capabilities {
	switch kind {
	case types.TargetKindDocker:
		return types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindScript, types.WorkloadKindJob, types.WorkloadKindContainer, types.WorkloadKindService},
			Resources:     types.ResourceCapability{CPU: true, Memory: true},
			Accounting:    types.AccountingCapability{CostEstimate: true, RateCard: "local"},
			Isolation:     types.IsolationCapability{Levels: []string{"container"}},
			Observability: types.ObservabilityCapability{Logs: true, Artifacts: true},
		}
	case types.TargetKindSSH:
		return types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindScript, types.WorkloadKindJob, types.WorkloadKindContainer, types.WorkloadKindService},
			Resources:     types.ResourceCapability{CPU: true, Memory: true},
			Networking:    types.NetworkingCapability{PublicEndpoint: true, PrivateVPCAccess: true},
			Accounting:    types.AccountingCapability{CostEstimate: true, RateCard: "ssh"},
			Isolation:     types.IsolationCapability{Levels: []string{"process", "container"}},
			Observability: types.ObservabilityCapability{Logs: true, Artifacts: true},
		}
	case types.TargetKindKubernetes:
		return types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindJob, types.WorkloadKindContainer, types.WorkloadKindService, types.WorkloadKindGPUJob},
			Resources:     types.ResourceCapability{CPU: true, Memory: true, GPU: types.GPUCapability{Supported: true}},
			Networking:    types.NetworkingCapability{PublicEndpoint: true, PrivateVPCAccess: true},
			Accounting:    types.AccountingCapability{CostEstimate: true, RateCard: "internal"},
			Isolation:     types.IsolationCapability{Levels: []string{"container", "dedicated-node"}},
			Observability: types.ObservabilityCapability{Logs: true, Metrics: true, Artifacts: true},
		}
	default:
		return types.Capabilities{
			WorkloadKinds: []types.WorkloadKind{types.WorkloadKindScript, types.WorkloadKindJob},
			Resources:     types.ResourceCapability{CPU: true, Memory: true},
			Accounting:    types.AccountingCapability{CostEstimate: true},
			Observability: types.ObservabilityCapability{Logs: true},
		}
	}
}
