package types

import "time"

// Confidence represents the confidence level of an estimate.
type Confidence string

const (
	ConfidenceHigh    Confidence = "high"
	ConfidenceMedium  Confidence = "medium"
	ConfidenceLow     Confidence = "low"
	ConfidenceUnknown Confidence = "unknown"
)

// OptimizeGoal is what the plan should optimize for.
type OptimizeGoal string

const (
	OptimizeCost  OptimizeGoal = "lowest-cost-success"
	OptimizeSpeed OptimizeGoal = "fastest-success"
)

// CostEstimate represents a cost prediction with confidence and assumptions.
type CostEstimate struct {
	Value       float64    `yaml:"value" json:"value"`
	Currency    string     `yaml:"currency" json:"currency"`
	Confidence  Confidence `yaml:"confidence" json:"confidence"`
	Assumptions []string   `yaml:"assumptions,omitempty" json:"assumptions,omitempty"`
	Exclusions  []string   `yaml:"exclusions,omitempty" json:"exclusions,omitempty"`
	// InstanceType is the cloud instance the estimate was priced against, set
	// when the estimate comes from the catalog. Carried so provisioning can
	// launch the instance that was actually priced. Empty for non-catalog
	// estimates (local/docker/rate-card).
	InstanceType string `yaml:"instanceType,omitempty" json:"instanceType,omitempty"`
}

// PlanMetadata contains identification and audit info.
type PlanMetadata struct {
	ID        string    `yaml:"id" json:"id"`
	CreatedAt time.Time `yaml:"createdAt" json:"createdAt"`
	CreatedBy string    `yaml:"createdBy" json:"createdBy"`
}

// PlanConstraints captures user constraints on the plan.
type PlanConstraints struct {
	TargetScope         string        `yaml:"targetScope" json:"targetScope"`
	OptimizeFor         OptimizeGoal  `yaml:"optimizeFor" json:"optimizeFor"`
	MaxEstimatedCostUSD float64       `yaml:"maxEstimatedCostUsd,omitempty" json:"maxEstimatedCostUsd,omitempty"`
	MaxDuration         time.Duration `yaml:"maxDuration,omitempty" json:"maxDuration,omitempty"`
	RequireGPU          string        `yaml:"requireGpu,omitempty" json:"requireGpu,omitempty"`
	TargetName          string        `yaml:"targetName,omitempty" json:"targetName,omitempty"`
	// WatchdogTTL bounds how long a cloud VM lives after dispatcher stops
	// heartbeating it. Zero = use adapter default (30 minutes).
	WatchdogTTL time.Duration `yaml:"watchdogTtl,omitempty" json:"watchdogTtl,omitempty"`
	// RetryTransientFailures, when set, retries workload execution once if
	// the failure is classified as transient (OOM kill, network glitch).
	// Default false — most workloads aren't idempotent.
	RetryTransientFailures bool `yaml:"retryTransientFailures,omitempty" json:"retryTransientFailures,omitempty"`
	// AllowSSHFrom, when set to a CIDR (e.g. 203.0.113.4/32), attaches a
	// per-run firewall to the provisioned cloud VM allowing inbound SSH only
	// from that range. Empty = no per-run firewall (provider defaults apply).
	// Supported on Hetzner and GCP; other providers reject a non-empty value.
	AllowSSHFrom string `yaml:"allowSshFrom,omitempty" json:"allowSshFrom,omitempty"`
}

// Recommendation is the primary target recommendation.
type Recommendation struct {
	Target        string       `yaml:"target" json:"target"`
	Runtime       string       `yaml:"runtime" json:"runtime"`
	EstimatedCost CostEstimate `yaml:"estimatedCost" json:"estimatedCost"`
	Reason        []string     `yaml:"reason" json:"reason"`
}

// Alternative is an alternative target option.
type Alternative struct {
	Target        string       `yaml:"target" json:"target"`
	Runtime       string       `yaml:"runtime" json:"runtime"`
	EstimatedCost CostEstimate `yaml:"estimatedCost" json:"estimatedCost"`
	Tradeoff      []string     `yaml:"tradeoff" json:"tradeoff"`
}

// RejectedTarget is a target that was evaluated but rejected.
type RejectedTarget struct {
	Target string `yaml:"target" json:"target"`
	Reason string `yaml:"reason" json:"reason"`
}

// Risk describes a potential issue with a plan.
type Risk struct {
	Category    string `yaml:"category" json:"category"`
	Description string `yaml:"description" json:"description"`
}

// ValidationResult captures the result of plan validation.
type ValidationResult struct {
	Schema             ValidationStatus `yaml:"schema" json:"schema"`
	PackageBuild       ValidationStatus `yaml:"packageBuild" json:"packageBuild"`
	TargetCapabilities ValidationStatus `yaml:"targetCapabilities" json:"targetCapabilities"`
	Credentials        ValidationStatus `yaml:"credentials" json:"credentials"`
	Quota              ValidationStatus `yaml:"quota" json:"quota"`
	Network            ValidationStatus `yaml:"network" json:"network"`
	Policy             ValidationStatus `yaml:"policy" json:"policy"`
	CostEstimate       ValidationStatus `yaml:"costEstimate" json:"costEstimate"`
	CleanupPlan        ValidationStatus `yaml:"cleanupPlan" json:"cleanupPlan"`
}

// ValidationStatus is the outcome of a single validation check.
type ValidationStatus string

const (
	ValidationPass    ValidationStatus = "pass"
	ValidationFail    ValidationStatus = "fail"
	ValidationSkipped ValidationStatus = "skipped"
	ValidationWarn    ValidationStatus = "warn"
)

// IsValid returns true if no validation checks failed.
func (v ValidationResult) IsValid() bool {
	for _, s := range []ValidationStatus{
		v.Schema, v.PackageBuild, v.TargetCapabilities,
		v.Credentials, v.Quota, v.Network, v.Policy,
		v.CostEstimate, v.CleanupPlan,
	} {
		if s == ValidationFail {
			return false
		}
	}
	return true
}

// PolicyRequirement represents an approval that must be obtained.
type PolicyRequirement struct {
	Name   string `yaml:"name" json:"name"`
	Reason string `yaml:"reason" json:"reason"`
}

// Plan is the full structured recommendation per design doc section 10.
type Plan struct {
	APIVersion  string          `yaml:"apiVersion" json:"apiVersion"`
	Kind        string          `yaml:"kind" json:"kind"`
	Metadata    PlanMetadata    `yaml:"metadata" json:"metadata"`
	Workload    WorkloadSpec    `yaml:"workload" json:"workload"`
	Constraints PlanConstraints `yaml:"constraints" json:"constraints"`

	Recommendation    *Recommendation     `yaml:"recommendation,omitempty" json:"recommendation,omitempty"`
	Alternatives      []Alternative       `yaml:"alternatives,omitempty" json:"alternatives,omitempty"`
	Rejected          []RejectedTarget    `yaml:"rejected,omitempty" json:"rejected,omitempty"`
	Risks             []Risk              `yaml:"risks,omitempty" json:"risks,omitempty"`
	Validation        ValidationResult    `yaml:"validation" json:"validation"`
	RequiredApprovals []PolicyRequirement `yaml:"requiredApprovals,omitempty" json:"requiredApprovals,omitempty"`
	ExecutionSteps    []string            `yaml:"executionSteps,omitempty" json:"executionSteps,omitempty"`
}
