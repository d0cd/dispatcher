package cost

import (
	"fmt"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
)

// DefaultDurationHours is the assumed runtime when duration is unknown.
const DefaultDurationHours = 1.0

// RateCard defines hourly rates for a target.
type RateCard struct {
	CPUPerHour    float64
	MemoryPerHour float64
	GPUPerHour    float64
	BasePerHour   float64
}

// rateCards maps target rate card names to their pricing.
var rateCards = map[string]RateCard{
	"local": {
		BasePerHour: 0.0, // marginal cost
	},
	"ssh": {
		BasePerHour: 0.10,
	},
	"internal": {
		CPUPerHour:    0.04,
		MemoryPerHour: 0.005,
		GPUPerHour:    1.50,
		BasePerHour:   0.02,
	},
	"modal": {
		CPUPerHour:    0.07,
		MemoryPerHour: 0.01,
		GPUPerHour:    2.50,
		BasePerHour:   0.05,
	},
	"e2b": {
		BasePerHour: 0.10,
	},
	"aws": {
		CPUPerHour:    0.05,
		MemoryPerHour: 0.007,
		GPUPerHour:    3.00,
		BasePerHour:   0.10,
	},
	"gcp": {
		CPUPerHour:    0.04,
		MemoryPerHour: 0.005,
		GPUPerHour:    2.80,
		BasePerHour:   0.08,
	},
	"azure": {
		CPUPerHour:    0.05,
		MemoryPerHour: 0.007,
		GPUPerHour:    3.00,
		BasePerHour:   0.10,
	},
	"hetzner": {
		CPUPerHour:    0.003,
		MemoryPerHour: 0.001,
		GPUPerHour:    1.95,
		BasePerHour:   0.003,
	},
}

// EstimateCost produces a cost estimate for running a workload on a target.
func EstimateCost(w types.WorkloadSpec, t types.TargetConfig) types.CostEstimate {
	card, ok := rateCards[t.Capabilities.Accounting.RateCard]
	if !ok {
		return types.CostEstimate{
			Currency:   "USD",
			Confidence: types.ConfidenceUnknown,
			Assumptions: []string{"no rate card available for target"},
		}
	}

	hours := DefaultDurationHours
	var assumptions []string
	var exclusions []string

	assumptions = append(assumptions, "assumes 1h runtime")

	if w.DetectedKind == types.WorkloadKindService {
		hours = 24.0
		assumptions = []string{"assumes 24h runtime for service"}
	}

	total := card.BasePerHour * hours

	if card.CPUPerHour > 0 {
		cpuCount := parseCPU(w.Requirements.CPU)
		total += card.CPUPerHour * float64(cpuCount) * hours
	}

	if w.Requirements.GPU.Required && card.GPUPerHour > 0 {
		gpuCount := w.Requirements.GPU.Count
		if gpuCount == 0 {
			gpuCount = 1
		}
		total += card.GPUPerHour * float64(gpuCount) * hours
	}

	exclusions = append(exclusions, "excludes network egress")
	exclusions = append(exclusions, "excludes storage after run")

	confidence := types.ConfidenceMedium
	if t.Capabilities.Accounting.RateCard == "local" {
		confidence = types.ConfidenceHigh
	}
	if w.DetectedKind == types.WorkloadKindGPUJob {
		confidence = types.ConfidenceLow
	}

	// Round to 2 decimal places
	total = float64(int(total*100)) / 100

	return types.CostEstimate{
		Value:       total,
		Currency:    "USD",
		Confidence:  confidence,
		Assumptions: assumptions,
		Exclusions:  exclusions,
	}
}

// EstimateCostWithHistory uses historical run data to improve estimates.
// Falls back to the standard rate-card estimate if no history is available.
func EstimateCostWithHistory(w types.WorkloadSpec, t types.TargetConfig, history *HistoryStore) types.CostEstimate {
	base := EstimateCost(w, t)

	if history == nil {
		return base
	}

	// Use historical duration if available
	histDuration := history.EstimateDuration(t.ID, string(w.DetectedKind))
	if histDuration > 0 {
		card, ok := rateCards[t.Capabilities.Accounting.RateCard]
		if ok {
			hours := histDuration.Hours()
			total := card.BasePerHour * hours
			cpuCount := parseCPU(w.Requirements.CPU)
			total += card.CPUPerHour * float64(cpuCount) * hours
			if w.Requirements.GPU.Required && card.GPUPerHour > 0 {
				gpuCount := w.Requirements.GPU.Count
				if gpuCount == 0 {
					gpuCount = 1
				}
				total += card.GPUPerHour * float64(gpuCount) * hours
			}
			total = float64(int(total*100)) / 100

			base.Value = total
			base.Assumptions = []string{
				fmt.Sprintf("based on historical median runtime of %s", histDuration.Round(time.Second)),
			}
		}
	}

	// Use historical confidence if available
	if histConf := history.ConfidenceForTarget(t.ID); histConf != "" {
		base.Confidence = histConf
		base.Assumptions = append(base.Assumptions, "confidence based on historical cost accuracy")
	}

	return base
}

func parseCPU(cpu string) int {
	if cpu == "" {
		return 2 // default
	}
	// Simple parsing: try to get a number
	n := 0
	for _, c := range cpu {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	if n == 0 {
		return 2
	}
	return n
}
