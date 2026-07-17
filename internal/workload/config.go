package workload

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
	"gopkg.in/yaml.v3"
)

// envRefPattern matches ${VAR} and ${VAR:-default}. Only the braced form is
// expanded — a bare $VAR (e.g. inside a shell command meant to expand on the
// remote host) is left untouched.
var envRefPattern = regexp.MustCompile(`\$\{([^}]+)\}`)
var resourceMemoryPattern = regexp.MustCompile(`(?i)^([0-9]+(?:\.[0-9]+)?)(?:g|gi|gb|m|mi|mb)?$`)

// expandEnvRefs substitutes ${VAR} / ${VAR:-default} references in the raw
// config against the process environment. An undefined ${VAR} with no default
// is an error rather than a silent empty string.
func expandEnvRefs(raw []byte) ([]byte, error) {
	var firstErr error
	out := envRefPattern.ReplaceAllFunc(raw, func(match []byte) []byte {
		inner := string(match[2 : len(match)-1]) // strip "${" and "}"
		name, def, hasDefault := strings.Cut(inner, ":-")
		// Substitution happens on the raw pre-parse bytes, so a value containing a
		// newline would inject additional top-level YAML keys (e.g. raising a cost
		// cap). Reject line breaks in a substituted value — a scalar config value
		// never legitimately spans lines.
		reject := func(v string) bool {
			if strings.ContainsAny(v, "\n\r") {
				if firstErr == nil {
					firstErr = fmt.Errorf("environment variable ${%s} contains a line break; refusing to inject it into the config", name)
				}
				return true
			}
			return false
		}
		if v, ok := os.LookupEnv(name); ok {
			if reject(v) {
				return match
			}
			return []byte(v)
		}
		if hasDefault {
			if reject(def) {
				return match
			}
			return []byte(def)
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("references undefined environment variable ${%s} (use ${%s:-default} to give a fallback)", name, name)
		}
		return match
	})
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// DispatcherConfig is the user-facing dispatcher.yaml structure.
type DispatcherConfig struct {
	Name    string             `yaml:"name"`
	Image   string             `yaml:"image,omitempty"`
	Command []string           `yaml:"command,omitempty"`
	CPU     string             `yaml:"cpu,omitempty"`
	Memory  string             `yaml:"memory,omitempty"`
	Arch    string             `yaml:"arch,omitempty"`
	GPU     *DispatchGPUConfig `yaml:"gpu,omitempty"`
	Service *DispatchService   `yaml:"service,omitempty"`
	Sandbox bool               `yaml:"sandbox,omitempty"`
	// Confidential requests a TEE-backed (memory-encrypted) VM. Presence means
	// "required"; the block selects the TEE type and attestation policy.
	Confidential *DispatchConfidentialConfig `yaml:"confidential,omitempty"`
	MaxCost      float64                     `yaml:"maxCost,omitempty"`
	MaxTime      string                      `yaml:"maxTime,omitempty"`
	Target       string                      `yaml:"target,omitempty"`
	// Region pins the cloud region/zone (overridden by the --region flag).
	Region string `yaml:"region,omitempty"`
	// Outputs lists workload-relative paths that should be retrieved before
	// the VM is destroyed (e.g. ["results/", "model.bin"]). When empty,
	// dispatcher attempts to retrieve a default "outputs/" directory if it
	// exists. Critical for cloud workloads: without this, workload-produced
	// artifacts (results, crash dumps, partial outputs) are lost on cleanup.
	Outputs []string `yaml:"outputs,omitempty"`
	// WatchdogTTL bounds how long a cloud VM lives after dispatcher stops
	// heartbeating it (e.g. "30m", "2h"). Defaults to 30m. Lower values
	// shrink your worst-case bill if dispatcher dies; higher values give you
	// more grace to reconnect.
	WatchdogTTL string `yaml:"watchdogTtl,omitempty"`
	// RetryTransientFailures, when set, retries workload execution once after a
	// transient failure. Pointer so an unset value is distinguishable from
	// false, letting the CLI flag take precedence during merge.
	RetryTransientFailures *bool `yaml:"retryTransientFailures,omitempty"`
	// Shard fans the workload out across many runs; Aggregate controls how the
	// shards' outputs are collected and how a shard failure is handled.
	Shard     *DispatchShardConfig     `yaml:"shard,omitempty"`
	Aggregate *DispatchAggregateConfig `yaml:"aggregate,omitempty"`
}

// DispatchShardConfig describes fan-out in dispatcher.yaml.
type DispatchShardConfig struct {
	Count       int    `yaml:"count,omitempty"`       // fixed shard count
	Discover    string `yaml:"discover,omitempty"`    // command whose stdout lines are work items
	MaxParallel int    `yaml:"maxParallel,omitempty"` // cap on concurrent shards (0 = engine default)
}

// DispatchAggregateConfig describes how shard outputs are collected.
type DispatchAggregateConfig struct {
	Outputs        []string `yaml:"outputs,omitempty"`        // per-shard paths to collect + merge
	OnShardFailure string   `yaml:"onShardFailure,omitempty"` // fail | retry | continue
}

// DispatchConfidentialConfig describes confidential-computing requirements in
// dispatcher.yaml. Type defaults to "any"; Attestation defaults to "required".
type DispatchConfidentialConfig struct {
	Type         string   `yaml:"type,omitempty"`         // sev | sev-snp | tdx | any
	Profile      string   `yaml:"profile,omitempty"`      // azure-snp | nitro (measured backend); empty = standard
	Attestation  string   `yaml:"attestation,omitempty"`  // required | off
	Measurements []string `yaml:"measurements,omitempty"` // exact launch-measurement allowlist (hex), R7
	MinTCB       uint64   `yaml:"minTCB,omitempty"`       // minimum acceptable reported TCB
}

// DispatchGPUConfig describes GPU requirements in dispatcher.yaml.
type DispatchGPUConfig struct {
	Count     int    `yaml:"count"`
	Model     string `yaml:"model,omitempty"`
	Framework string `yaml:"framework,omitempty"`
}

// DispatchService describes service configuration in dispatcher.yaml.
type DispatchService struct {
	Port int `yaml:"port"`
}

// LoadConfig reads dispatcher.yaml from the given directory.
// Returns nil if no config file is found (not an error).
//
// Decoded in strict mode (KnownFields) so a typo like `maxxCost: 5` raises
// an error instead of being silently dropped. The previous lenient decode
// let users believe they had set a cap when they hadn't.
func LoadConfig(dir string) (*DispatcherConfig, error) {
	for _, name := range []string{"dispatcher.yaml", "dispatcher.yml"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		data, err = expandEnvRefs(data)
		if err != nil {
			return nil, fmt.Errorf("%s %w", path, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		var cfg DispatcherConfig
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w (did you mistype a field name? known fields are name, image, command, cpu, memory, arch, gpu, service, sandbox, confidential, shard, aggregate, maxCost, maxTime, target, region, outputs, watchdogTtl, retryTransientFailures)", path, err)
		}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("validate %s: %w", path, err)
		}
		return &cfg, nil
	}
	return nil, nil
}

// Validate enforces semantic constraints that strict decoding can't catch:
// MaxCost must be non-negative, MaxTime/WatchdogTTL must parse as
// durations, etc. Run by LoadConfig; callers constructing DispatcherConfig
// programmatically can invoke it directly.
// isSafeImageRef accepts a conservative container image-reference charset
// ([registry/]repo[:tag][@digest]) and rejects a leading '-' (so the value can't
// be read as a docker flag) plus any whitespace/shell metacharacter.
func isSafeImageRef(s string) bool {
	if s == "" || s[0] == '-' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '/' || r == ':' || r == '@' || r == '-':
		default:
			return false
		}
	}
	return true
}

func (c *DispatcherConfig) Validate() error {
	// The image ref flows verbatim into `docker run` argv; a value beginning with
	// '-' (or carrying whitespace/shell metacharacters) would be parsed as a docker
	// flag (e.g. `-v/:/host` mounts the host root into the container). Fail closed at
	// the config boundary so an untrusted repo's dispatcher.yaml can't inject flags.
	if c.Image != "" && !isSafeImageRef(c.Image) {
		return fmt.Errorf("image %q is not a valid image reference (must not begin with '-' or contain whitespace/metacharacters)", c.Image)
	}
	if c.CPU != "" {
		cpu, err := strconv.Atoi(strings.TrimSpace(c.CPU))
		if err != nil || cpu <= 0 {
			return fmt.Errorf("cpu must be a positive integer (got %q)", c.CPU)
		}
	}
	if c.Memory != "" {
		match := resourceMemoryPattern.FindStringSubmatch(strings.TrimSpace(c.Memory))
		if len(match) == 0 {
			return fmt.Errorf("memory must be a positive size such as 30G or 2048M (got %q)", c.Memory)
		}
		amount, err := strconv.ParseFloat(match[1], 64)
		if err != nil || amount <= 0 {
			return fmt.Errorf("memory must be positive (got %q)", c.Memory)
		}
	}
	switch c.Arch {
	case "", "x86_64", "arm64":
	default:
		return fmt.Errorf("arch %q is invalid (x86_64|arm64)", c.Arch)
	}
	if c.MaxCost < 0 {
		return fmt.Errorf("maxCost must be non-negative (got %v)", c.MaxCost)
	}
	if c.MaxTime != "" {
		if _, err := time.ParseDuration(c.MaxTime); err != nil {
			return fmt.Errorf("maxTime %q is not a valid duration: %w", c.MaxTime, err)
		}
	}
	if c.WatchdogTTL != "" {
		if _, err := time.ParseDuration(c.WatchdogTTL); err != nil {
			return fmt.Errorf("watchdogTtl %q is not a valid duration: %w", c.WatchdogTTL, err)
		}
	}
	if c.Service != nil && (c.Service.Port < 0 || c.Service.Port > 65535) {
		return fmt.Errorf("service.port out of range: %d", c.Service.Port)
	}
	if c.GPU != nil && c.GPU.Count < 0 {
		return fmt.Errorf("gpu.count must be non-negative")
	}
	if c.Confidential != nil {
		switch c.Confidential.Type {
		case "", "any", "sev", "sev-snp", "tdx":
		default:
			return fmt.Errorf("confidential.type %q is invalid (sev|sev-snp|tdx|any)", c.Confidential.Type)
		}
		switch c.Confidential.Profile {
		case "", "azure-snp", "nitro":
		default:
			return fmt.Errorf("confidential.profile %q is invalid (azure-snp|nitro)", c.Confidential.Profile)
		}
		switch c.Confidential.Attestation {
		case "", "required", "off":
		default:
			return fmt.Errorf("confidential.attestation %q is invalid (required|off)", c.Confidential.Attestation)
		}
	}
	if c.Shard != nil {
		if c.Shard.Count < 0 {
			return fmt.Errorf("shard.count must be non-negative (got %d)", c.Shard.Count)
		}
		if c.Shard.MaxParallel < 0 {
			return fmt.Errorf("shard.maxParallel must be non-negative (got %d)", c.Shard.MaxParallel)
		}
	}
	if c.Aggregate != nil {
		switch c.Aggregate.OnShardFailure {
		case "", "fail", "retry", "continue":
		default:
			return fmt.Errorf("aggregate.onShardFailure %q is invalid (fail|retry|continue)", c.Aggregate.OnShardFailure)
		}
	}
	return nil
}

// ApplyConfig merges a DispatcherConfig into a WorkloadSpec.
// Config values take precedence over auto-detected values.
func ApplyConfig(spec *types.WorkloadSpec, cfg *DispatcherConfig) {
	if cfg == nil {
		return
	}

	if cfg.Name != "" {
		spec.Name = cfg.Name
	}

	if len(cfg.Command) > 0 {
		spec.Command = cfg.Command
		if spec.DetectedKind == "" || spec.DetectedKind == types.WorkloadKindUnknown {
			spec.DetectedKind = types.WorkloadKindScript
		}
	}

	if cfg.CPU != "" {
		spec.Requirements.CPU = cfg.CPU
	}
	if cfg.Memory != "" {
		spec.Requirements.Memory = cfg.Memory
	}
	if cfg.Arch != "" {
		spec.Requirements.Arch = cfg.Arch
	}

	if cfg.Image != "" {
		// Pre-built image: skip the build step entirely, run the image as-is.
		// BaseImage is the field DockerAdapter reads to construct the run
		// command; PackageTypeImage tells it NOT to mount the workload source
		// (the user is running a packaged tool, not their own code).
		spec.Package = types.PackagePlan{
			Type:          types.PackageTypeImage,
			BaseImage:     cfg.Image,
			BuildRequired: false,
		}
		// Pre-built images by themselves don't have inspectable source, so
		// the auto-detector leaves DetectedKind=Unknown — which makes
		// feasibility reject every target. Treat a configured image as a
		// short-lived script unless explicitly overridden (e.g. by
		// cfg.Service which classifies the same workload as a service).
		if spec.DetectedKind == types.WorkloadKindUnknown {
			spec.DetectedKind = types.WorkloadKindScript
		}
	}

	if cfg.Confidential != nil {
		attestation := cfg.Confidential.Attestation
		if attestation == "" {
			attestation = "required" // secure default
		}
		spec.Requirements.Confidential = types.ConfidentialRequirement{
			Required:     true,
			Type:         cfg.Confidential.Type,
			Profile:      cfg.Confidential.Profile,
			Attestation:  attestation,
			Measurements: cfg.Confidential.Measurements,
			MinTCB:       cfg.Confidential.MinTCB,
		}
	}

	if cfg.Shard != nil {
		spec.Shard.Count = cfg.Shard.Count
		spec.Shard.Discover = cfg.Shard.Discover
		spec.Shard.MaxParallel = cfg.Shard.MaxParallel
	}
	if cfg.Aggregate != nil {
		// aggregate.outputs describes the paths every shard must retrieve before
		// the host can aggregate them. Adapters consume WorkloadSpec.Outputs, so
		// populate both fields; keeping Shard.Outputs preserves the aggregation
		// contract while Outputs makes collection actually happen.
		aggregateOutputs := sanitizeOutputs(cfg.Aggregate.Outputs)
		spec.Shard.Outputs = aggregateOutputs
		spec.Outputs = aggregateOutputs
		spec.Shard.OnShardFailure = cfg.Aggregate.OnShardFailure
	}

	if cfg.GPU != nil {
		spec.Requirements.GPU = types.GPURequirement{
			Required:  true,
			Count:     cfg.GPU.Count,
			Model:     cfg.GPU.Model,
			Framework: cfg.GPU.Framework,
		}
		if spec.Requirements.GPU.Count == 0 {
			spec.Requirements.GPU.Count = 1
		}
		spec.DetectedKind = types.WorkloadKindGPUJob
	}

	if cfg.Service != nil && cfg.Service.Port > 0 {
		// Add port if not already detected
		found := false
		for _, p := range spec.Ports {
			if p == cfg.Service.Port {
				found = true
				break
			}
		}
		if !found {
			spec.Ports = append(spec.Ports, cfg.Service.Port)
		}
		spec.DetectedKind = types.WorkloadKindService
	}

	if cfg.Sandbox {
		// Sandbox is an isolation requirement, not a workload kind: keep the
		// detected kind and let feasibility filter to isolated targets.
		spec.Requirements.Sandbox = true
	}

	if len(cfg.Outputs) > 0 {
		// Explicit top-level outputs override auto-detection, while any explicit
		// per-shard aggregate outputs remain included.
		spec.Outputs = mergeOutputs(sanitizeOutputs(cfg.Outputs), spec.Shard.Outputs)
	}
}

func mergeOutputs(existing, additional []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(additional))
	out := make([]string, 0, len(existing)+len(additional))
	for _, group := range [][]string{existing, additional} {
		for _, p := range group {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// sanitizeOutputs rejects entries that would let the workload escape the
// retrieval directory: absolute paths and any path containing `..` segments.
// Paths must be workload-relative (e.g. "results/", "model.bin"). Bad entries
// are dropped with a warning to stderr — silently ignoring them would leave
// the user thinking a known-bad path was retrieved.
//
// Defense against artifact path-traversal: a malicious or careless workload
// config could otherwise have rsync write retrieved files to `/etc/passwd`.
func sanitizeOutputs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p == "" {
			continue
		}
		if filepath.IsAbs(p) {
			fmt.Fprintf(os.Stderr, "warning: ignoring absolute outputs path %q (must be workload-relative)\n", p)
			continue
		}
		// Reject any path containing "..", INCLUDING interior segments like
		// "a/../b": the artifact adapters (Local/SSH) reject the same at retrieval,
		// so accepting it here would silently drop a declared output. Match their
		// check exactly rather than normalize (which would also strip a meaningful
		// trailing slash from an rsync path).
		if strings.Contains(p, "..") {
			fmt.Fprintf(os.Stderr, "warning: ignoring outputs path %q (path traversal)\n", p)
			continue
		}
		out = append(out, p)
	}
	return out
}
