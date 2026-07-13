package types

// WorkloadKind classifies the type of workload detected.
type WorkloadKind string

const (
	WorkloadKindScript    WorkloadKind = "script"
	WorkloadKindJob       WorkloadKind = "job"
	WorkloadKindService   WorkloadKind = "service"
	WorkloadKindGPUJob    WorkloadKind = "gpu-job"
	WorkloadKindSandbox   WorkloadKind = "sandbox"
	WorkloadKindContainer WorkloadKind = "container"
	WorkloadKindUnknown   WorkloadKind = "unknown"
)

// Runtime identifies the language/runtime of a workload.
type Runtime string

const (
	RuntimePython  Runtime = "python"
	RuntimeNode    Runtime = "node"
	RuntimeGo      Runtime = "go"
	RuntimeRust    Runtime = "rust"
	RuntimeJava    Runtime = "java"
	RuntimeRuby    Runtime = "ruby"
	RuntimeUnknown Runtime = "unknown"
)

// PackageType describes how the workload should be packaged.
type PackageType string

const (
	PackageTypeContainer PackageType = "container"
	PackageTypeScript    PackageType = "script"
	PackageTypeImage     PackageType = "image"
)

// GPURequirement describes GPU needs for a workload.
type GPURequirement struct {
	Required  bool   `yaml:"required" json:"required"`
	Count     int    `yaml:"count,omitempty" json:"count,omitempty"`
	Model     string `yaml:"model,omitempty" json:"model,omitempty"`
	Framework string `yaml:"framework,omitempty" json:"framework,omitempty"`
}

// ResourceRequirements describes compute resources needed.
type ResourceRequirements struct {
	CPU    string         `yaml:"cpu,omitempty" json:"cpu,omitempty"`
	Memory string         `yaml:"memory,omitempty" json:"memory,omitempty"`
	GPU    GPURequirement `yaml:"gpu" json:"gpu"`
	// Confidential, when Required, demands a TEE-backed VM (hardware-encrypted
	// memory: AMD SEV/SEV-SNP, Intel TDX). Only confidential-capable
	// targets/instances offering the requested Type are feasible.
	Confidential ConfidentialRequirement `yaml:"confidential,omitempty" json:"confidential,omitempty"`
}

// ConfidentialRequirement describes a workload's confidential-computing demand.
type ConfidentialRequirement struct {
	Required bool `yaml:"required" json:"required"`
	// Type is the TEE technology: "sev" | "sev-snp" | "tdx" | "" (any).
	Type string `yaml:"type,omitempty" json:"type,omitempty"`
	// Profile selects a measured-boot attestation backend, orthogonal to Type:
	// "azure-snp" (direct SNP+vTPM, agent measured into PCR11) or "nitro" (AWS
	// Nitro Enclaves). Empty means the target's standard backend (GCP
	// Confidential Space, Azure MAA, or AWS SEV-SNP).
	Profile string `yaml:"profile,omitempty" json:"profile,omitempty"`
	// Attestation is "required" (default — the run only proceeds after the TEE
	// report verifies) or "off" (provision the TEE but skip verification).
	Attestation string `yaml:"attestation,omitempty" json:"attestation,omitempty"`
	// Measurements is the EXACT allowlist of acceptable launch measurements (hex)
	// the verifier enforces (R7). An empty allowlist fails closed under
	// attestation: required — there is no genuine measurement to trust.
	Measurements []string `yaml:"measurements,omitempty" json:"measurements,omitempty"`
	// MinTCB is the minimum acceptable reported TCB/firmware version. Reports
	// below it are rejected as running known-vulnerable platform firmware.
	MinTCB uint64 `yaml:"minTCB,omitempty" json:"minTCB,omitempty"`
}

// PackagePlan describes how to package a workload for execution.
type PackagePlan struct {
	Type          PackageType `yaml:"type" json:"type"`
	Dockerfile    string      `yaml:"dockerfile,omitempty" json:"dockerfile,omitempty"`
	BuildRequired bool        `yaml:"buildRequired" json:"buildRequired"`
	BaseImage     string      `yaml:"baseImage,omitempty" json:"baseImage,omitempty"`
}

// SecretRef is a reference to a secret or credential found in the workload.
type SecretRef struct {
	Kind     string `yaml:"kind" json:"kind"`
	Location string `yaml:"location" json:"location"`
	Name     string `yaml:"name" json:"name"`
}

// DataRequirement describes a data dependency.
type DataRequirement struct {
	Kind     string `yaml:"kind" json:"kind"`
	Location string `yaml:"location" json:"location"`
	Details  string `yaml:"details,omitempty" json:"details,omitempty"`
}

// WorkloadSpec is the detected shape of a workload after inspection.
type WorkloadSpec struct {
	Name         string               `yaml:"name" json:"name"`
	DetectedKind WorkloadKind         `yaml:"detectedKind" json:"detectedKind"`
	Source       WorkloadSource       `yaml:"source" json:"source"`
	Runtime      Runtime              `yaml:"runtime" json:"runtime"`
	Entrypoints  []string             `yaml:"entrypoints,omitempty" json:"entrypoints,omitempty"`
	Package      PackagePlan          `yaml:"package" json:"package"`
	Command      []string             `yaml:"command,omitempty" json:"command,omitempty"`
	Ports        []int                `yaml:"ports,omitempty" json:"ports,omitempty"`
	Requirements ResourceRequirements `yaml:"requirements" json:"requirements"`
	Secrets      []SecretRef          `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Data         []DataRequirement    `yaml:"data,omitempty" json:"data,omitempty"`
	// Outputs lists workload-relative paths that adapters retrieve from
	// remote execution targets before teardown. Populated by dispatcher.yaml
	// or by auto-detecting a default `outputs/` directory.
	Outputs []string `yaml:"outputs,omitempty" json:"outputs,omitempty"`
	// Shard, when Enabled, fans this workload out across many runs. Populated
	// from the dispatcher.yaml `shard:` / `aggregate:` blocks.
	Shard ShardSpec `yaml:"shard,omitempty" json:"shard,omitempty"`
	// Env is extra runtime environment injected into the workload alongside its
	// .env (Env wins on conflict). Used to hand a shard its SHARD_INDEX/
	// SHARD_COUNT identity. Runtime-only — it never affects the build.
	Env map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
}

// WorkloadSource identifies where the workload came from.
type WorkloadSource struct {
	Type string `yaml:"type" json:"type"`
	Path string `yaml:"path" json:"path"`
}
