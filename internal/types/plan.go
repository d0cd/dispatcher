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
	APIVersion string           `yaml:"apiVersion" json:"apiVersion"`
	Kind       string           `yaml:"kind" json:"kind"`
	Metadata   PlanMetadata     `yaml:"metadata" json:"metadata"`
	Workload   WorkloadSpec     `yaml:"workload" json:"workload"`
	Constraints PlanConstraints `yaml:"constraints" json:"constraints"`

	Recommendation    *Recommendation     `yaml:"recommendation,omitempty" json:"recommendation,omitempty"`
	Alternatives      []Alternative       `yaml:"alternatives,omitempty" json:"alternatives,omitempty"`
	Rejected          []RejectedTarget    `yaml:"rejected,omitempty" json:"rejected,omitempty"`
	Risks             []Risk              `yaml:"risks,omitempty" json:"risks,omitempty"`
	Validation        ValidationResult    `yaml:"validation" json:"validation"`
	RequiredApprovals []PolicyRequirement `yaml:"requiredApprovals,omitempty" json:"requiredApprovals,omitempty"`
	ExecutionSteps    []string            `yaml:"executionSteps,omitempty" json:"executionSteps,omitempty"`
}
