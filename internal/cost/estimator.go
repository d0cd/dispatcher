package cost

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/cloudvm"
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

// rateCards covers non-cloud target kinds and provides the offline fallback
// for cloud providers when no live catalog is supplied. Cloud-vm targets
// derive their prices from the live catalog when one is available, falling
// back here only for tests and offline use. The blended cloud entries are
// intentionally rough — surfacing with ConfidenceLow tells the user not to
// trust them as much as live or rate-card data.
var rateCards = map[string]RateCard{
	"local": {
		BasePerHour: 0.0,
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
	"aws":     {CPUPerHour: 0.05, MemoryPerHour: 0.007, GPUPerHour: 3.00, BasePerHour: 0.10},
	"gcp":     {CPUPerHour: 0.04, MemoryPerHour: 0.005, GPUPerHour: 2.80, BasePerHour: 0.08},
	"azure":   {CPUPerHour: 0.05, MemoryPerHour: 0.007, GPUPerHour: 3.00, BasePerHour: 0.10},
	"hetzner": {CPUPerHour: 0.003, MemoryPerHour: 0.001, GPUPerHour: 1.95, BasePerHour: 0.003},
}

// EstimateCost produces a cost estimate for running a workload on a target.
//
// For cloud-vm targets, when catalog is non-nil and contains pricing for the
// target's provider, the estimate is derived from the cheapest matching
// instance. When catalog is nil or has no data for the provider, cloud-vm
// targets return ConfidenceUnknown — we won't pretend to know cloud prices
// without live data.
//
// Non-cloud targets always use static rate cards.
func EstimateCost(spec types.WorkloadSpec, t types.TargetConfig, catalog *cloudvm.Catalog) types.CostEstimate {
	if t.Kind == types.TargetKindCloudVM && catalog != nil {
		if est, ok := estimateFromCatalog(spec, t, catalog); ok {
			return est
		}
		// Catalog had no data for this provider — fall through to the static
		// rate card so we degrade gracefully instead of surfacing Unknown.
	}
	est := estimateFromRateCard(spec, t)
	// Resolve a GPU instance type from the static catalog even when live pricing
	// is unavailable, so a GPU workload isn't refused offline for lack of a
	// resolved instance. This fills in WHICH instance only — the price and
	// confidence stay from the rate card so we don't pretend to know live prices.
	if t.Kind == types.TargetKindCloudVM && spec.Requirements.GPU.Required && est.InstanceType == "" {
		est.InstanceType = staticGPUInstance(spec, t)
	}
	return est
}

// staticGPUInstance resolves the cheapest static-catalog instance matching the
// workload's GPU requirement for the target's provider, or "" if none exists
// (e.g. an unrecognized model, or a provider with no GPU SKU).
func staticGPUInstance(spec types.WorkloadSpec, t types.TargetConfig) string {
	provider, ok := rateCardToProvider(t.Capabilities.Accounting.RateCard)
	if !ok {
		return ""
	}
	matches := cloudvm.NewCatalog().FindCheapestForProvider(provider, requirementsFromSpec(spec))
	if len(matches) == 0 {
		return ""
	}
	return matches[0].Name
}

// estimateFromCatalog returns (estimate, true) when the catalog has a matching
// instance for the target's provider. Returns (_, false) when the caller
// should fall back to the static rate card.
func estimateFromCatalog(spec types.WorkloadSpec, t types.TargetConfig, catalog *cloudvm.Catalog) (types.CostEstimate, bool) {
	provider, ok := rateCardToProvider(t.Capabilities.Accounting.RateCard)
	if !ok {
		return types.CostEstimate{}, false
	}

	req := requirementsFromSpec(spec)
	matches := catalog.FindCheapestForProvider(provider, req)
	if len(matches) == 0 {
		return types.CostEstimate{}, false
	}
	cheapest := matches[0]

	hours := assumedHours(spec)
	total := cheapest.PricePerHour * hours

	assumptions := []string{
		fmt.Sprintf("based on %s (%dvCPU/%.0fGB) at $%.4f/h", cheapest.Name, cheapest.VCPUs, cheapest.MemoryGB, cheapest.PricePerHour),
		fmt.Sprintf("assumes %s runtime", durationLabel(hours)),
	}

	confidence := types.ConfidenceMedium
	if spec.DetectedKind == types.WorkloadKindGPUJob {
		confidence = types.ConfidenceLow
	}

	return types.CostEstimate{
		Value:        roundCents(total),
		Currency:     "USD",
		Confidence:   confidence,
		Assumptions:  assumptions,
		Exclusions:   []string{"excludes network egress", "excludes storage after run"},
		InstanceType: cheapest.Name,
	}, true
}

func estimateFromRateCard(spec types.WorkloadSpec, t types.TargetConfig) types.CostEstimate {
	card, ok := rateCards[t.Capabilities.Accounting.RateCard]
	if !ok {
		return types.CostEstimate{
			Currency:    "USD",
			Confidence:  types.ConfidenceUnknown,
			Assumptions: []string{"no rate card available for target"},
		}
	}

	hours := assumedHours(spec)
	assumptions := []string{fmt.Sprintf("assumes %s runtime", durationLabel(hours))}

	total := card.BasePerHour * hours
	if card.CPUPerHour > 0 {
		cpuCount := parseCPU(spec.Requirements.CPU)
		total += card.CPUPerHour * float64(cpuCount) * hours
	}
	if card.MemoryPerHour > 0 {
		total += card.MemoryPerHour * parseMemoryGB(spec.Requirements.Memory) * hours
	}
	if spec.Requirements.GPU.Required && card.GPUPerHour > 0 {
		gpuCount := spec.Requirements.GPU.Count
		if gpuCount == 0 {
			gpuCount = 1
		}
		total += card.GPUPerHour * float64(gpuCount) * hours
	}

	confidence := types.ConfidenceMedium
	if t.Capabilities.Accounting.RateCard == "local" {
		confidence = types.ConfidenceHigh
	}
	if spec.DetectedKind == types.WorkloadKindGPUJob {
		confidence = types.ConfidenceLow
	}
	// Cloud rate cards are stale fallbacks (used only when no live catalog
	// data exists); downgrade their confidence so the recommendation surface
	// doesn't make them look as trustworthy as live data.
	if _, isCloud := rateCardToProvider(t.Capabilities.Accounting.RateCard); isCloud {
		confidence = types.ConfidenceLow
		assumptions = append(assumptions, "fallback: live pricing unavailable for this provider")
	}

	return types.CostEstimate{
		Value:       roundCents(total),
		Currency:    "USD",
		Confidence:  confidence,
		Assumptions: assumptions,
		Exclusions:  []string{"excludes network egress", "excludes storage after run"},
	}
}

// EstimateCostWithHistory adjusts EstimateCost's hours using historical run data.
func EstimateCostWithHistory(spec types.WorkloadSpec, t types.TargetConfig, history *HistoryStore, catalog *cloudvm.Catalog) types.CostEstimate {
	base := EstimateCost(spec, t, catalog)
	if history == nil || base.Confidence == types.ConfidenceUnknown {
		return base
	}

	histDuration := history.EstimateDuration(t.ID, string(spec.DetectedKind))
	if histDuration > 0 {
		hours := histDuration.Hours()
		// Re-run the cost calculation with the historical hours.
		scaled := scaleEstimateToHours(spec, t, catalog, hours)
		scaled.Assumptions = append(scaled.Assumptions,
			fmt.Sprintf("based on historical median runtime of %s", histDuration.Round(time.Second)))
		base = scaled
	}
	if histConf := history.ConfidenceForTarget(t.ID); histConf != "" {
		base.Confidence = histConf
		base.Assumptions = append(base.Assumptions, "confidence based on historical cost accuracy")
	}
	return base
}

// scaleEstimateToHours re-derives the estimate with a specific hours value
// (used when historical data tells us the typical runtime).
func scaleEstimateToHours(spec types.WorkloadSpec, t types.TargetConfig, catalog *cloudvm.Catalog, hours float64) types.CostEstimate {
	if t.Kind == types.TargetKindCloudVM && catalog != nil {
		provider, ok := rateCardToProvider(t.Capabilities.Accounting.RateCard)
		if ok {
			matches := catalog.FindCheapestForProvider(provider, requirementsFromSpec(spec))
			if len(matches) > 0 {
				total := matches[0].PricePerHour * hours
				return types.CostEstimate{
					Value:        roundCents(total),
					Currency:     "USD",
					Confidence:   types.ConfidenceMedium,
					InstanceType: matches[0].Name,
				}
			}
		}
	}
	card, ok := rateCards[t.Capabilities.Accounting.RateCard]
	if !ok {
		return types.CostEstimate{Currency: "USD", Confidence: types.ConfidenceUnknown}
	}
	total := card.BasePerHour * hours
	if card.CPUPerHour > 0 {
		total += card.CPUPerHour * float64(parseCPU(spec.Requirements.CPU)) * hours
	}
	if card.MemoryPerHour > 0 {
		total += card.MemoryPerHour * parseMemoryGB(spec.Requirements.Memory) * hours
	}
	if spec.Requirements.GPU.Required && card.GPUPerHour > 0 {
		count := spec.Requirements.GPU.Count
		if count == 0 {
			count = 1
		}
		total += card.GPUPerHour * float64(count) * hours
	}
	return types.CostEstimate{Value: roundCents(total), Currency: "USD", Confidence: types.ConfidenceMedium}
}

func rateCardToProvider(card string) (cloudvm.ProviderID, bool) {
	switch card {
	case "aws":
		return cloudvm.ProviderAWS, true
	case "gcp":
		return cloudvm.ProviderGCP, true
	case "azure":
		return cloudvm.ProviderAzure, true
	case "hetzner":
		return cloudvm.ProviderHetzner, true
	}
	return "", false
}

func requirementsFromSpec(spec types.WorkloadSpec) cloudvm.InstanceRequirements {
	req := cloudvm.InstanceRequirements{
		MinVCPUs: parseCPU(spec.Requirements.CPU),
	}
	if mem := parseMemoryGB(spec.Requirements.Memory); mem > 0 {
		req.MinMemoryGB = mem
	}
	if spec.Requirements.GPU.Required {
		count := spec.Requirements.GPU.Count
		if count == 0 {
			count = 1
		}
		req.GPUCount = count
		// An explicit hardware pin (e.g. model: h100) constrains the match; an
		// unset model lets the catalog return the cheapest matching GPU. The
		// freeform Framework field (e.g. pytorch) is not a hardware model and is
		// intentionally not used here.
		req.GPUModel = spec.Requirements.GPU.Model
	}
	return req
}

func assumedHours(spec types.WorkloadSpec) float64 {
	if spec.DetectedKind == types.WorkloadKindService {
		return 24.0
	}
	return DefaultDurationHours
}

func durationLabel(hours float64) string {
	if hours == DefaultDurationHours {
		return "1h"
	}
	return fmt.Sprintf("%.0fh", hours)
}

// roundCents rounds to four decimal places (1/100 of a cent) so the stored
// value preserves sub-cent runs — a 90-second cax11 run at €0.005/h is
// real money to track, even if it displays as <$0.01. Whole-cent truncation
// (the previous behavior) was silently zeroing every cheap Hetzner run.
func roundCents(v float64) float64 { return float64(int(v*10000)) / 10000 }

func parseCPU(cpu string) int {
	if cpu == "" {
		return 2
	}
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

// parseMemoryGB extracts a GB value from strings like "4G", "8Gi", "16GB", "2048M".
// Returns 0 when the string can't be parsed.
func parseMemoryGB(s string) float64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}
	var numEnd int
	for i, c := range s {
		if (c >= '0' && c <= '9') || c == '.' {
			numEnd = i + 1
		} else {
			break
		}
	}
	if numEnd == 0 {
		return 0
	}
	n, err := strconv.ParseFloat(s[:numEnd], 64)
	if err != nil {
		return 0
	}
	unit := s[numEnd:]
	switch {
	case strings.HasPrefix(unit, "g"):
		return n
	case strings.HasPrefix(unit, "m"):
		return n / 1024
	}
	return n // assume GB
}
