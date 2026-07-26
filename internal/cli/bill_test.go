package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/cost"
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
	amount, currency, services, _, err := parseAWSCost(raw, false)
	require.NoError(t, err)
	assert.InDelta(t, 12.34, amount, 0.001)
	assert.Equal(t, "USD", currency)
	assert.Empty(t, services)
}

func TestParseAWSCost_ByService(t *testing.T) {
	raw := []byte(`{"ResultsByTime":[{"Groups":[
		{"Keys":["Amazon Elastic Compute Cloud - Compute"],"Metrics":{"UnblendedCost":{"Amount":"7.00","Unit":"USD"}}},
		{"Keys":["Amazon Simple Storage Service"],"Metrics":{"UnblendedCost":{"Amount":"3.50","Unit":"USD"}}}]}]}`)
	amount, currency, services, _, err := parseAWSCost(raw, true)
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
	amount, currency, services, _, err := parseGCPBillingRows(raw)
	require.NoError(t, err)
	assert.InDelta(t, 5.00, amount, 0.001)
	assert.Equal(t, "USD", currency)
	require.Len(t, services, 2)
}

// Summing across currencies is meaningless and an unparseable row understates
// the total — both must be flagged, not hidden.
func TestParseAWSCost_MixedCurrencyAndDroppedRow(t *testing.T) {
	raw := []byte(`{"ResultsByTime":[{"Groups":[
		{"Keys":["A"],"Metrics":{"UnblendedCost":{"Amount":"7.00","Unit":"USD"}}},
		{"Keys":["B"],"Metrics":{"UnblendedCost":{"Amount":"3.00","Unit":"EUR"}}},
		{"Keys":["C"],"Metrics":{"UnblendedCost":{"Amount":"not-a-number","Unit":"USD"}}}]}]}`)
	_, currency, _, note, err := parseAWSCost(raw, true)
	require.NoError(t, err)
	assert.Equal(t, "MIXED", currency, "more than one currency must not be summed under a single label")
	assert.Contains(t, note, "unparseable", "a dropped row must be surfaced")
	assert.Contains(t, note, "currencies")
}

// parseAzureCost consumes a Microsoft.CostManagement/query response (columns +
// rows), not the deprecated `az consumption usage list` shape (which returns
// pretaxCost:"None" for many subscriptions and silently zeroed the total).
func TestParseAzureCost(t *testing.T) {
	raw := []byte(`{"properties":{
		"columns":[{"name":"PreTaxCost"},{"name":"ServiceName"},{"name":"Currency"}],
		"rows":[[0.2749,"Virtual Machines","USD"],[0.0680,"Virtual Network","USD"],[0.0256,"Storage","USD"]]
	}}`)

	total, cur, svcs, note, err := parseAzureCost(raw, true)
	require.NoError(t, err)
	assert.InDelta(t, 0.3685, total, 0.0001, "sums PreTaxCost across all rows")
	assert.Equal(t, "USD", cur)
	assert.Empty(t, note, "well-formed rows drop nothing")
	require.Len(t, svcs, 3)
	assert.Equal(t, "Virtual Machines", svcs[0].Name, "sorted by amount desc")

	// Without by-service, the total is still correct but no breakdown is produced.
	total2, _, svcs2, _, err := parseAzureCost(raw, false)
	require.NoError(t, err)
	assert.InDelta(t, 0.3685, total2, 0.0001)
	assert.Empty(t, svcs2)
}

// buildAzureCostQuery filters to dispatcher-tagged resources by default and drops
// the filter under --all; ServiceName grouping only when a breakdown is asked for.
func TestBuildAzureCostQuery(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)

	tagged := buildAzureCostQuery(start, end, false, false)
	assert.Contains(t, tagged, "\"dispatcher\"", "default query filters to dispatcher-tagged spend")
	assert.NotContains(t, tagged, "ServiceName", "no grouping without --by-service")

	allSvc := buildAzureCostQuery(start, end, true, true)
	assert.NotContains(t, allSvc, "dispatcher", "--all drops the tag filter")
	assert.Contains(t, allSvc, "ServiceName", "--by-service groups by ServiceName")
	assert.Contains(t, allSvc, "2026-07-01", "carries the start of the window")
}

type billRow struct {
	Provider  string  `json:"provider"`
	Amount    float64 `json:"amount"`
	Available bool    `json:"available"`
	Estimate  float64 `json:"estimate"`
}

func runBillJSON(t *testing.T, args ...string) map[string]billRow {
	t.Helper()
	stdout := captureStdout(t, func() {
		_, _, err := executeCommand(append([]string{"--output", "json", "bill"}, args...)...)
		require.NoError(t, err)
	})
	var rows []billRow
	require.NoError(t, json.Unmarshal([]byte(stdout), &rows))
	byP := map[string]billRow{}
	for _, r := range rows {
		byP[r.Provider] = r
	}
	return byP
}

// A provider whose auth probe fails is reported unavailable; one that returns a
// figure is available with that amount.
func TestBill_JSON_AuthFailAndAmount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prevExec, prevLook := billExec, billLookPath
	billLookPath = func(string) (string, error) { return "/usr/bin/stub", nil } // all CLIs "present"
	billExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case name == "aws" && strings.Contains(joined, "sts"):
			return nil, assert.AnError // aws auth probe fails -> unavailable
		case name == "az" && strings.Contains(joined, "account show"):
			return []byte("sub-123"), nil
		case name == "az" && strings.Contains(joined, "CostManagement"):
			return []byte(`{"properties":{"columns":[{"name":"PreTaxCost"},{"name":"Currency"}],"rows":[[2.50,"USD"]]}}`), nil
		}
		return []byte("{}"), nil
	}
	t.Cleanup(func() { billExec, billLookPath = prevExec, prevLook })

	byP := runBillJSON(t)
	assert.False(t, byP["aws"].Available, "aws auth probe failed -> unavailable")
	assert.True(t, byP["azure"].Available, "azure returned a figure")
	assert.InDelta(t, 2.50, byP["azure"].Amount, 0.01)
}

// --reconcile populates the dispatcher-tracked estimate; --all suppresses it
// (reconcile is only meaningful against the tagged scope).
func TestBill_Reconcile_EstimateGatedByAll(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	hist, err := cost.NewHistoryStore()
	require.NoError(t, err)
	require.NoError(t, hist.Record(cost.RunHistory{
		RunID: "r1", TargetID: "aws-vm", ActualCost: 0.06, CompletedAt: time.Now().UTC(), Success: true}))

	prevExec, prevLook := billExec, billLookPath
	billLookPath = func(string) (string, error) { return "/usr/bin/stub", nil }
	billExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "aws" && strings.Contains(strings.Join(args, " "), "get-cost-and-usage") {
			return []byte(`{"ResultsByTime":[{"Total":{"UnblendedCost":{"Amount":"0.00","Unit":"USD"}}}]}`), nil
		}
		return []byte("{}"), nil
	}
	t.Cleanup(func() { billExec, billLookPath = prevExec, prevLook })

	withReconcile := runBillJSON(t, "--reconcile")
	assert.InDelta(t, 0.06, withReconcile["aws"].Estimate, 0.001, "reconcile populates the estimate from run history")

	withAll := runBillJSON(t, "--reconcile", "--all")
	assert.Less(t, withAll["aws"].Estimate, 0.0, "--all suppresses reconcile (estimate not computed)")
}

func TestValidGCPBillingTable(t *testing.T) {
	// Valid fully-qualified BigQuery table (project may hyphenate; dataset/table
	// are word chars).
	assert.True(t, validGCPBillingTable("finops-502014.billing_export.gcp_billing_export_v1_01ED3F_AEE40B_2EA468"))

	// Injection attempts and malformed inputs must be rejected.
	assert.False(t, validGCPBillingTable("`x` UNION SELECT secret_col AS net, 'USD' AS currency FROM `other.d.t` -- "),
		"a backtick that escapes the identifier quoting must be rejected")
	assert.False(t, validGCPBillingTable("proj.dataset"), "must be fully qualified project.dataset.table")
	assert.False(t, validGCPBillingTable("proj.dataset.table; DROP TABLE x"))
	assert.False(t, validGCPBillingTable("proj.dataset.table WHERE 1=1"))
	assert.False(t, validGCPBillingTable(""))
}

func TestProviderTargetID(t *testing.T) {
	assert.Equal(t, "aws-vm", providerTargetID("aws"))
	assert.Equal(t, "azure-vm", providerTargetID("azure"))
	assert.Equal(t, "gcp-vm", providerTargetID("gcp"))
	assert.Equal(t, "hetzner-vm", providerTargetID("hetzner"))
}
