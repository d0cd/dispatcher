package cloudvm

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOCIPrices(t *testing.T) {
	// Standard E4/E5/A1 OCPU+Memory rows, plus an "E4 Ax" (must NOT poison E4) and
	// a VMware BM row (must be ignored).
	raw := []byte(`{"items":[
		{"displayName":"Compute - Standard - E4 - OCPU","metricName":"OCPU Per Hour","currencyCodeLocalizations":[{"prices":[{"model":"PAY_AS_YOU_GO","value":0.025}]}]},
		{"displayName":"Compute - Standard - E4  - Memory","metricName":"Gigabyte Per Hour","currencyCodeLocalizations":[{"prices":[{"model":"PAY_AS_YOU_GO","value":0.0015}]}]},
		{"displayName":"Compute - Standard - E5 - OCPU","metricName":"OCPU Per Hour","currencyCodeLocalizations":[{"prices":[{"model":"PAY_AS_YOU_GO","value":0.03}]}]},
		{"displayName":"Compute - Standard - E5 - Memory","metricName":"Gigabytes Per Hour","currencyCodeLocalizations":[{"prices":[{"model":"PAY_AS_YOU_GO","value":0.002}]}]},
		{"displayName":"Compute - Standard - A1 - OCPU","metricName":"OCPU Per Hour","currencyCodeLocalizations":[{"prices":[{"model":"PAY_AS_YOU_GO","value":0.01}]}]},
		{"displayName":"Compute - Standard - A1 - Memory","metricName":"Gigabytes Per Hour","currencyCodeLocalizations":[{"prices":[{"model":"PAY_AS_YOU_GO","value":0.0015}]}]},
		{"displayName":"OCI - Compute - Standard - E4 Ax - OCPU","metricName":"OCPU Per Hour","currencyCodeLocalizations":[{"prices":[{"model":"PAY_AS_YOU_GO","value":99}]}]},
		{"displayName":"Oracle Cloud VMware Solution - BM.Standard.E5.48","metricName":"Node Per Hour","currencyCodeLocalizations":[{"prices":[{"model":"PAY_AS_YOU_GO","value":16}]}]}
	]}`)
	got, err := parseOCIPrices(raw)
	require.NoError(t, err)

	byName := map[string]InstanceType{}
	for _, i := range got {
		byName[i.Name] = i
	}
	// E4: 2*0.025 + 16*0.0015 = 0.074 (matches the old static price — model verified)
	assert.InDelta(t, 0.074, byName["VM.Standard.E4.Flex"].PricePerHour, 1e-9)
	// E5: 4*0.03 + 32*0.002 = 0.184
	assert.InDelta(t, 0.184, byName["VM.Standard.E5.Flex"].PricePerHour, 1e-9)
	// A1: 2*0.01 + 12*0.0015 = 0.038
	assert.InDelta(t, 0.038, byName["VM.Standard.A1.Flex"].PricePerHour, 1e-9)
	assert.Equal(t, "arm64", byName["VM.Standard.A1.Flex"].Arch)
	// The "E4 Ax" row (99) must not have poisoned the E4 rate.
	assert.Less(t, byName["VM.Standard.E4.Flex"].PricePerHour, 1.0)
}

func TestParseOCIPrices_NoRatesIsError(t *testing.T) {
	_, err := parseOCIPrices([]byte(`{"items":[{"displayName":"Storage","metricName":"GB"}]}`))
	require.Error(t, err)
}

// Live check against Oracle's real price list (opt-in). Confirms the parser tracks
// the live API shape and produces sensible prices for the offered Flex shapes.
func TestOCIFetcher_Live(t *testing.T) {
	if os.Getenv("DISPATCHER_OCI_PRICING_LIVE") == "" {
		t.Skip("set DISPATCHER_OCI_PRICING_LIVE=1 to hit the live OCI price list")
	}
	insts, err := NewOCIFetcher().Fetch(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, insts, "must price at least one OCI Flex shape from live data")
	for _, i := range insts {
		t.Logf("%-22s %dvCPU/%.0fGB %s $%.4f/h", i.Name, i.VCPUs, i.MemoryGB, i.Arch, i.PricePerHour)
		assert.True(t, isPlausibleHourlyPrice(i.PricePerHour), "%s price %.4f implausible", i.Name, i.PricePerHour)
		assert.Equal(t, ProviderOCI, i.Provider)
	}
}
