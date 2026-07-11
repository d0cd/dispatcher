package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/d0cd/dispatcher/internal/types"
)

func planWith(target string, c types.ConfidentialRequirement) *types.Plan {
	return &types.Plan{
		Recommendation: &types.Recommendation{Target: target},
		Workload:       types.WorkloadSpec{Requirements: types.ResourceRequirements{Confidential: c}},
	}
}

func TestUsesConfidentialSpace(t *testing.T) {
	cases := []struct {
		name   string
		plan   *types.Plan
		expect bool
	}{
		{"confidential gcp → container path", planWith("gcp-vm", types.ConfidentialRequirement{Required: true}), true},
		{"attestation off falls back to SSH path", planWith("gcp-vm", types.ConfidentialRequirement{Required: true, Attestation: "off"}), false},
		{"non-confidential gcp", planWith("gcp-vm", types.ConfidentialRequirement{}), false},
		{"confidential but not gcp", planWith("aws-vm", types.ConfidentialRequirement{Required: true}), false},
		{"confidential azure is not the CS path", planWith("azure-vm", types.ConfidentialRequirement{Required: true}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, usesConfidentialSpace(tc.plan))
		})
	}
}

func TestUsesAzureConfidential(t *testing.T) {
	cases := []struct {
		name   string
		plan   *types.Plan
		expect bool
	}{
		{"confidential azure → MAA path", planWith("azure-vm", types.ConfidentialRequirement{Required: true}), true},
		{"attestation off stays on SSH path", planWith("azure-vm", types.ConfidentialRequirement{Required: true, Attestation: "off"}), false},
		{"non-confidential azure", planWith("azure-vm", types.ConfidentialRequirement{}), false},
		{"confidential gcp is not the azure path", planWith("gcp-vm", types.ConfidentialRequirement{Required: true}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, usesAzureConfidential(tc.plan))
		})
	}
}
