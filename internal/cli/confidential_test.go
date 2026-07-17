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

func TestUsesAzureSNP(t *testing.T) {
	cases := []struct {
		name   string
		plan   *types.Plan
		expect bool
	}{
		{"azure-snp profile on azure → measured path", planWith("azure-vm", types.ConfidentialRequirement{Required: true, Profile: "azure-snp"}), true},
		{"default type is the MAA path, not measured", planWith("azure-vm", types.ConfidentialRequirement{Required: true}), false},
		{"attestation off stays on SSH path", planWith("azure-vm", types.ConfidentialRequirement{Required: true, Profile: "azure-snp", Attestation: "off"}), false},
		{"azure-snp on aws is not the azure path", planWith("aws-vm", types.ConfidentialRequirement{Required: true, Profile: "azure-snp"}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, usesAzureSNP(tc.plan))
		})
	}
}

func TestUsesAWSNitro(t *testing.T) {
	cases := []struct {
		name   string
		plan   *types.Plan
		expect bool
	}{
		{"nitro profile on aws → nitro path", planWith("aws-vm", types.ConfidentialRequirement{Required: true, Profile: "nitro"}), true},
		{"sev-snp type is not the nitro path", planWith("aws-vm", types.ConfidentialRequirement{Required: true, Type: "sev-snp"}), false},
		{"default type is not the nitro path", planWith("aws-vm", types.ConfidentialRequirement{Required: true}), false},
		{"attestation off stays on SSH path", planWith("aws-vm", types.ConfidentialRequirement{Required: true, Profile: "nitro", Attestation: "off"}), false},
		{"nitro profile on gcp is not the aws nitro path", planWith("gcp-vm", types.ConfidentialRequirement{Required: true, Profile: "nitro"}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, usesAWSNitro(tc.plan))
		})
	}
}
