package cost

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
)

func cloudTarget(rateCard string) types.TargetConfig {
	return types.TargetConfig{Capabilities: types.Capabilities{
		Accounting: types.AccountingCapability{RateCard: rateCard}}}
}

func TestApplySpot_DiscountsAndLowersConfidence(t *testing.T) {
	base := types.CostEstimate{Value: 2.00, Currency: "USD", Confidence: types.ConfidenceMedium}

	gcp := ApplySpot(base, cloudTarget("gcp"))
	assert.InDelta(t, 0.60, gcp.Value, 0.001, "gcp spot ~30% of on-demand")
	assert.Equal(t, types.ConfidenceLow, gcp.Confidence)
	assert.NotEmpty(t, gcp.Assumptions, "must record the spot-estimate assumption")

	aws := ApplySpot(base, cloudTarget("aws"))
	assert.InDelta(t, 0.70, aws.Value, 0.001, "aws spot ~35%")

	oci := ApplySpot(base, cloudTarget("oci"))
	assert.InDelta(t, 1.00, oci.Value, 0.001, "oci preemptible ~50%")
}

// A live spot ratio from the catalog overrides the per-provider discount factor.
func TestApplySpot_LiveRatioOverridesFactor(t *testing.T) {
	base := types.CostEstimate{Value: 2.00, Currency: "USD", Confidence: types.ConfidenceMedium, SpotRatio: 0.22}
	got := ApplySpot(base, cloudTarget("gcp"))
	assert.InDelta(t, 0.44, got.Value, 0.001, "live ratio 0.22 used, not the 0.30 gcp factor")
	assert.Equal(t, types.ConfidenceLow, got.Confidence, "spot is volatile/possibly-stale, so confidence is Low")
	if assert.NotEmpty(t, got.Assumptions) {
		assert.Contains(t, got.Assumptions[len(got.Assumptions)-1], "spot pricing")
	}
}

func TestApplySpot_NonSpotProviderUnchanged(t *testing.T) {
	base := types.CostEstimate{Value: 5.00, Confidence: types.ConfidenceHigh}
	// A provider with no spot factor (e.g. hetzner/local) is returned as-is.
	got := ApplySpot(base, cloudTarget("hetzner"))
	assert.Equal(t, base, got)
}
