package target

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// ErrNoTargetsOutput means the source has no dispatcher_targets output, so an
// import is a no-op (the managed file is left untouched) rather than a
// delete-all.
var ErrNoTargetsOutput = errors.New("no dispatcher_targets output found")

// TerraformOptions configures the --from-terraform source.
type TerraformOptions struct {
	Binary         string // "terraform" (default) or "tofu"
	Workspace      string // TF workspace to read; empty = the currently-selected one
	AllowSensitive bool   // import even if the dispatcher_targets output is marked sensitive
}

// runTF runs `<binary> -chdir=<dir> output -json`, returning stdout and stderr
// separately. It's a package-level seam so the terraform path is tested without
// a real binary. `output` is read-only — it never refreshes state or mutates
// resources.
var runTF = func(ctx context.Context, binary, dir, workspace string) (stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, binary, "-chdir="+dir, "output", "-json")
	if workspace != "" {
		cmd.Env = append(os.Environ(), "TF_WORKSPACE="+workspace)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// tfErrorHint derives a safe, actionable hint from terraform's stderr WITHOUT
// echoing the raw stderr, which can carry unrelated secrets.
func tfErrorHint(stderr []byte) string {
	s := strings.ToLower(string(stderr))
	switch {
	case strings.Contains(s, "initiali"): // "has not been initialized", "terraform init"
		return " (run `terraform init` in that directory first)"
	case strings.Contains(s, "no state") || strings.Contains(s, "state file"):
		return " (no state — has the workspace been applied?)"
	case strings.Contains(s, "no configuration files") || strings.Contains(s, "not a directory"):
		return " (is that a Terraform workspace directory?)"
	default:
		return ""
	}
}

// FetchTerraformTargets runs `terraform output -json`, extracts the
// dispatcher_targets output's value (the {"targets":[...]} blob), and returns it
// ready for ImportFromJSON. Returns ErrNoTargetsOutput if the output is absent.
// Sensitive outputs are refused unless opts.AllowSensitive. The raw terraform
// output and stderr are never echoed — they may carry unrelated secrets.
func FetchTerraformTargets(ctx context.Context, dir string, opts TerraformOptions) (json.RawMessage, error) {
	binary := opts.Binary
	if binary == "" {
		binary = "terraform"
	}
	out, stderr, err := runTF(ctx, binary, dir, opts.Workspace)
	if err != nil {
		return nil, fmt.Errorf("%s output -json failed%s: %w", binary, tfErrorHint(stderr), err)
	}

	var outputs map[string]struct {
		Sensitive bool            `json:"sensitive"`
		Value     json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(out, &outputs); err != nil {
		return nil, fmt.Errorf("parse %s outputs", binary) // never include the raw bytes
	}
	o, ok := outputs["dispatcher_targets"]
	if !ok {
		return nil, ErrNoTargetsOutput
	}
	if o.Sensitive && !opts.AllowSensitive {
		return nil, fmt.Errorf("the dispatcher_targets output is marked sensitive; re-run with --allow-sensitive to import it")
	}
	return o.Value, nil
}

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

// ImportPlan is a computed-but-not-yet-written import: the targets to install
// plus the add/update/remove delta against the previous import. Commit writes it.
type ImportPlan struct {
	targets []types.TargetConfig
	Added   []string
	Updated []string
	Removed []string
}

// Targets returns the targets that would be written (for warning checks/preview).
func (p *ImportPlan) Targets() []types.TargetConfig { return p.targets }

// HasChanges reports whether committing would change anything.
func (p *ImportPlan) HasChanges() bool {
	return len(p.Added)+len(p.Updated)+len(p.Removed) > 0
}

// Commit atomically writes the planned targets to the managed import file.
func (p *ImportPlan) Commit() (string, error) {
	return WriteTargetsFile(managedImportFile, p.targets)
}

// PlanImport parses a dispatcher_targets blob and computes the import WITHOUT
// writing: it rejects collisions with any existing target that isn't one of its
// own previously-imported ones (builtins, hand-added <id>.yaml, or project
// dispatcher.yaml — load order would otherwise decide who wins), and computes
// the add/update/remove delta. An empty target list legitimately clears all
// previously imported targets.
func PlanImport(blob []byte) (*ImportPlan, error) {
	targets, err := ParseDispatcherTargets(blob)
	if err != nil {
		return nil, err
	}
	dir, err := state.Subdir("targets")
	if err != nil {
		return nil, err
	}
	managed := managedIDs(filepath.Join(dir, managedImportFile))

	reg := NewRegistry()
	reg.LoadBuiltins()
	_ = reg.LoadUserConfig()
	for _, t := range targets {
		if _, exists := reg.Get(t.ID); exists && !managed[t.ID] {
			return nil, fmt.Errorf("target %q already exists (builtin, hand-added, or project config); refusing to shadow it", t.ID)
		}
	}

	next := make(map[string]bool, len(targets))
	plan := &ImportPlan{targets: targets}
	for _, t := range targets {
		next[t.ID] = true
		if managed[t.ID] {
			plan.Updated = append(plan.Updated, t.ID)
		} else {
			plan.Added = append(plan.Added, t.ID)
		}
	}
	for id := range managed {
		if !next[id] {
			plan.Removed = append(plan.Removed, id)
		}
	}
	sort.Strings(plan.Added)
	sort.Strings(plan.Updated)
	sort.Strings(plan.Removed)
	return plan, nil
}

// ImportFromJSON plans and commits in one step (non-interactive callers/tests).
func ImportFromJSON(blob []byte) (*ImportResult, error) {
	plan, err := PlanImport(blob)
	if err != nil {
		return nil, err
	}
	path, err := plan.Commit()
	if err != nil {
		return nil, err
	}
	return &ImportResult{Path: path, Added: plan.Added, Updated: plan.Updated, Removed: plan.Removed}, nil
}

// expandTilde resolves a leading ~ in a path to the user's home directory, so
// an imported key_file is stored as an absolute path. Returns the input
// unchanged if it has no leading ~ or the home dir can't be resolved.
func expandTilde(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}

// KeyFileWarnings checks each target's key_file at import time and returns
// human-readable warnings for missing files or group/world-accessible perms —
// surfacing problems now rather than letting them fail opaquely at run time.
func KeyFileWarnings(targets []types.TargetConfig) []string {
	var warns []string
	for _, t := range targets {
		if t.SSH == nil || t.SSH.KeyFile == "" {
			continue
		}
		info, err := os.Stat(t.SSH.KeyFile)
		if err != nil {
			warns = append(warns, fmt.Sprintf("%s: key_file %q does not exist", t.ID, t.SSH.KeyFile))
			continue
		}
		if info.Mode().Perm()&0o077 != 0 {
			warns = append(warns, fmt.Sprintf("%s: key_file %q is group/world-accessible (%#o); ssh may refuse it", t.ID, t.SSH.KeyFile, info.Mode().Perm()))
		}
	}
	return warns
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
		ssh := &types.SSHTargetConfig{Host: e.SSH.Host, User: e.SSH.User, Port: e.SSH.Port, KeyFile: expandTilde(e.SSH.KeyFile)}
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
