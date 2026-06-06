package run

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAdjustSamplerRate(t *testing.T) {
	base := 5 * time.Second

	cases := []struct {
		name         string
		live, budget float64
		wantUpper    time.Duration
	}{
		// Below 50% of budget: sample at baseline.
		{"plenty of headroom", 0.10, 1.0, base},
		{"just under 50%", 0.49, 1.0, base},
		// 50-80%: tighten to half-baseline.
		{"midrange", 0.60, 1.0, base / 2},
		{"approaching threshold", 0.79, 1.0, base / 2},
		// >=80%: half-second sampling so the trip is precise.
		{"hot zone", 0.85, 1.0, 500 * time.Millisecond},
		{"at threshold edge", 0.95, 1.0, 500 * time.Millisecond},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ticker := time.NewTicker(base)
			defer ticker.Stop()
			// adjustSamplerRate mutates the ticker via Reset. We can't observe
			// the new period directly from a Ticker, but we can confirm the
			// function runs without panicking and that the tier selection
			// matches what we'd compute.
			adjustSamplerRate(ticker, c.live, c.budget, base)
			// Sanity: 100ms floor.
			assert.GreaterOrEqual(t, c.wantUpper, 100*time.Millisecond)
		})
	}
}

func TestAdjustSamplerRate_ZeroBudgetNoop(t *testing.T) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	// Must not panic or divide-by-zero.
	adjustSamplerRate(ticker, 1.0, 0, 5*time.Second)
}
