package cost

import (
	"fmt"

	"github.com/d0cd/dispatcher/internal/types"
)

// spotDiscount is the fraction of the on-demand price a spot/preemptible instance
// is *estimated* to cost, per provider rate card. Spot prices fluctuate (typically
// 60–90% off on-demand and vary by region/AZ minute to minute), so these are
// conservative rough factors applied at low confidence — an estimate, not a quote.
// GCP tends to discount deepest; Azure spot is more limited.
var spotDiscount = map[string]float64{
	"gcp":   0.30,
	"aws":   0.35,
	"azure": 0.40,
}

// ApplySpot rescales an on-demand estimate to an approximate spot price for a
// spot-capable cloud target and drops confidence to Low. A target whose provider
// has no known spot factor (non-cloud, or a provider without spot support) is
// returned unchanged.
func ApplySpot(est types.CostEstimate, t types.TargetConfig) types.CostEstimate {
	f, ok := spotDiscount[t.Capabilities.Accounting.RateCard]
	if !ok {
		return est
	}
	est.Value = roundCents(est.Value * f)
	est.Confidence = types.ConfidenceLow
	est.Assumptions = append(est.Assumptions,
		fmt.Sprintf("spot pricing estimated at ~%.0f%% of on-demand (actual fluctuates 60–90%% off and the instance can be reclaimed anytime)", f*100))
	return est
}
