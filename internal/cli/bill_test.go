package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var billStart = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
var billEnd = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

func TestAWSBillArgs(t *testing.T) {
	joined := func(args []string) string { return strings.Join(args, " ") }

	// Default: dispatcher-tagged only, no per-service grouping.
	def := awsBillArgs(billStart, billEnd, false, false)
	assert.Contains(t, joined(def), `"Key":"dispatcher"`, "default filters to dispatcher-tagged")
	assert.NotContains(t, joined(def), "--group-by")

	// --all drops the tag filter.
	all := awsBillArgs(billStart, billEnd, true, false)
	assert.NotContains(t, joined(all), "dispatcher", "--all must not filter by tag")

	// --by-service groups by SERVICE.
	svc := awsBillArgs(billStart, billEnd, true, true)
	assert.Contains(t, joined(svc), "--group-by")
	assert.Contains(t, joined(svc), "Type=DIMENSION,Key=SERVICE")
}

func TestParseAWSCost_Total(t *testing.T) {
	raw := []byte(`{"ResultsByTime":[{"Total":{"UnblendedCost":{"Amount":"12.34","Unit":"USD"}}}]}`)
	amount, currency, services, err := parseAWSCost(raw, false)
	require.NoError(t, err)
	assert.InDelta(t, 12.34, amount, 0.001)
	assert.Equal(t, "USD", currency)
	assert.Empty(t, services)
}

func TestParseAWSCost_ByService(t *testing.T) {
	raw := []byte(`{"ResultsByTime":[{"Groups":[
		{"Keys":["Amazon Elastic Compute Cloud - Compute"],"Metrics":{"UnblendedCost":{"Amount":"7.00","Unit":"USD"}}},
		{"Keys":["Amazon Simple Storage Service"],"Metrics":{"UnblendedCost":{"Amount":"3.50","Unit":"USD"}}}]}]}`)
	amount, currency, services, err := parseAWSCost(raw, true)
	require.NoError(t, err)
	assert.InDelta(t, 10.50, amount, 0.001, "total sums the service breakdown")
	assert.Equal(t, "USD", currency)
	require.Len(t, services, 2)
	assert.Equal(t, "Amazon Elastic Compute Cloud - Compute", services[0].Name)
	assert.InDelta(t, 7.00, services[0].Amount, 0.001)
}

func TestBuildGCPBillingSQL(t *testing.T) {
	tbl := "finops-502014.billing.gcp_billing_export_v1_ABC"

	tagged := buildGCPBillingSQL(tbl, billStart, billEnd, false, false)
	assert.Contains(t, tagged, tbl)
	assert.Contains(t, tagged, "usage_start_time")
	assert.Contains(t, tagged, "dispatcher", "tagged query filters on the dispatcher label")
	assert.NotContains(t, tagged, "GROUP BY service")

	all := buildGCPBillingSQL(tbl, billStart, billEnd, true, false)
	assert.NotContains(t, all, "dispatcher", "--all drops the label filter")

	svc := buildGCPBillingSQL(tbl, billStart, billEnd, true, true)
	assert.Contains(t, svc, "service.description")
}

func TestParseGCPBillingRows(t *testing.T) {
	// bq --format=json returns an array of row objects.
	raw := []byte(`[{"service":"Compute Engine","net":"4.20","currency":"USD"},
		{"service":"Cloud Storage","net":"0.80","currency":"USD"}]`)
	amount, currency, services, err := parseGCPBillingRows(raw)
	require.NoError(t, err)
	assert.InDelta(t, 5.00, amount, 0.001)
	assert.Equal(t, "USD", currency)
	require.Len(t, services, 2)
}

func TestParseAzureCost(t *testing.T) {
	raw := []byte(`[
		{"pretaxCost":"5.00","currency":"USD","consumedService":"Microsoft.Compute","tags":{"dispatcher":"true"}},
		{"pretaxCost":"2.00","currency":"USD","consumedService":"Microsoft.Storage","tags":{}}]`)

	// tagged only
	amt, _, _, err := parseAzureCost(raw, false, false)
	require.NoError(t, err)
	assert.InDelta(t, 5.00, amt, 0.001, "tagged mode counts only dispatcher=true rows")

	// all, by service
	amtAll, _, svcs, err := parseAzureCost(raw, true, true)
	require.NoError(t, err)
	assert.InDelta(t, 7.00, amtAll, 0.001, "--all counts every row")
	require.Len(t, svcs, 2)
}

func TestProviderTargetID(t *testing.T) {
	assert.Equal(t, "aws-vm", providerTargetID("aws"))
	assert.Equal(t, "azure-vm", providerTargetID("azure"))
	assert.Equal(t, "gcp-vm", providerTargetID("gcp"))
	assert.Equal(t, "hetzner-vm", providerTargetID("hetzner"))
}
