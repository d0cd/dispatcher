package workload

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
	"gopkg.in/yaml.v3"
)

// envRefPattern matches ${VAR} and ${VAR:-default}. Only the braced form is
// expanded — a bare $VAR (e.g. inside a shell command meant to expand on the
// remote host) is left untouched.
var envRefPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// expandEnvRefs substitutes ${VAR} / ${VAR:-default} references in the raw
// config against the process environment. An undefined ${VAR} with no default
// is an error rather than a silent empty string.
func expandEnvRefs(raw []byte) ([]byte, error) {
	var firstErr error
	out := envRefPattern.ReplaceAllFunc(raw, func(match []byte) []byte {
		inner := string(match[2 : len(match)-1]) // strip "${" and "}"
		name, def, hasDefault := strings.Cut(inner, ":-")
		if v, ok := os.LookupEnv(name); ok {
			return []byte(v)
		}
		if hasDefault {
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
	GPU     *DispatchGPUConfig `yaml:"gpu,omitempty"`
	Service *DispatchService   `yaml:"service,omitempty"`
	Sandbox bool               `yaml:"sandbox,omitempty"`
	// Confidential requests a TEE-backed (memory-encrypted) VM. Presence means
	// "required"; the block selects the TEE type and attestation policy.
	Confidential *DispatchConfidentialConfig `yaml:"confidential,omitempty"`
	MaxCost      float64                     `yaml:"maxCost,omitempty"`
	MaxTime      string                      `yaml:"maxTime,omitempty"`
	Target       string                      `yaml:"target,omitempty"`
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
}

// DispatchConfidentialConfig describes confidential-computing requirements in
// dispatcher.yaml. Type defaults to "any"; Attestation defaults to "required".
type DispatchConfidentialConfig struct {
	Type         string   `yaml:"type,omitempty"`         // sev | sev-snp | tdx | any
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
			return nil, fmt.Errorf("parse %s: %w (did you mistype a field name? known fields are name, image, command, gpu, service, sandbox, confidential, maxCost, maxTime, target, outputs, watchdogTtl, retryTransientFailures)", path, err)
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
func (c *DispatcherConfig) Validate() error {
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
		switch c.Confidential.Attestation {
		case "", "required", "off":
		default:
			return fmt.Errorf("confidential.attestation %q is invalid (required|off)", c.Confidential.Attestation)
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
			Attestation:  attestation,
			Measurements: cfg.Confidential.Measurements,
			MinTCB:       cfg.Confidential.MinTCB,
		}
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
		spec.DetectedKind = types.WorkloadKindSandbox
	}

	if len(cfg.Outputs) > 0 {
		spec.Outputs = sanitizeOutputs(cfg.Outputs)
	}
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
		// Reject any `..` segment. Use Clean to catch fancy variants like
		// "foo/../../etc" → "../etc".
		cleaned := filepath.Clean(p)
		if cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, `..\`) {
			fmt.Fprintf(os.Stderr, "warning: ignoring outputs path %q (path traversal)\n", p)
			continue
		}
		out = append(out, p)
	}
	return out
}
