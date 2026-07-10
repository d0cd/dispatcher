package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/cost"
)

var billFlags struct {
	all       bool
	byService bool
	reconcile bool
}

// billExec is the seam for running billing CLIs (aws/az/bq); tests override it.
var billExec = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// billLookPath is the seam for CLI-presence checks; tests override it so the
// orchestration is exercised regardless of what's installed.
var billLookPath = exec.LookPath

var billCmd = &cobra.Command{
	Use:         "bill",
	Annotations: map[string]string{supportsJSON: "true"},
	Short:       "Show spend month-to-date across configured clouds",
	Long: `Queries each cloud provider's billing API for the current calendar month.

By default it reports only resources tagged 'dispatcher=true'. Flags widen it:
  --all          every service's spend, not just dispatcher-tagged
  --by-service   break the total down by cloud service
  --reconcile    show dispatcher's tracked estimate next to the authoritative
                 bill, and the delta (a positive delta hints at untracked spend)

For each provider the command checks CLI presence, authentication, and
billing-read permission; providers where any fails are reported and skipped.

GCP billing has no direct CLI: set DISPATCHER_GCP_BILLING_TABLE to your
BigQuery export table (project.dataset.gcp_billing_export_v1_XXXXXX) and this
command queries it via bq.

Note: dispatcher's own per-run cost tracking (see 'dispatcher list',
'dispatcher cost <id>') uses sampled runtime and may drift 5-15% from the
authoritative provider totals shown here.`,
	RunE: runBill,
}

func init() {
	billCmd.Flags().BoolVar(&billFlags.all, "all", false, "include all spend, not just dispatcher-tagged resources")
	billCmd.Flags().BoolVar(&billFlags.byService, "by-service", false, "break spend down by cloud service")
	billCmd.Flags().BoolVar(&billFlags.reconcile, "reconcile", false, "compare dispatcher's tracked estimate against the authoritative bill (ignored with --all)")
	rootCmd.AddCommand(billCmd)
}

type serviceSpend struct {
	Name   string  `json:"service"`
	Amount float64 `json:"amount"`
}

type providerSpend struct {
	provider string
	amount   float64 // -1 means unavailable
	currency string
	note     string
	services []serviceSpend // populated with --by-service
	estimate float64        // dispatcher-tracked; -1 means not computed
}

func runBill(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)

	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)

	results := []providerSpend{
		awsSpend(ctx, monthStart, monthEnd, billFlags.all, billFlags.byService),
		azureSpend(ctx, monthStart, monthEnd, billFlags.all, billFlags.byService),
		gcpSpend(ctx, monthStart, monthEnd, billFlags.all, billFlags.byService),
		hetznerSpend(monthStart),
	}
	// Reconcile compares the authoritative bill against dispatcher's tracked
	// per-run estimate, so it is only meaningful against the dispatcher-tagged
	// scope. With --all the bill includes non-dispatcher spend, which would
	// guarantee a spurious positive delta — so skip it.
	if billFlags.reconcile && !billFlags.all {
		addEstimates(results, monthStart)
	}

	if jsonOutput() {
		type spendJSON struct {
			Provider  string         `json:"provider"`
			Amount    float64        `json:"amount"`
			Currency  string         `json:"currency"`
			Available bool           `json:"available"`
			Services  []serviceSpend `json:"services,omitempty"`
			Estimate  float64        `json:"estimate,omitempty"`
			Note      string         `json:"note,omitempty"`
		}
		rows := make([]spendJSON, 0, len(results))
		for _, r := range results {
			rows = append(rows, spendJSON{
				Provider:  r.provider,
				Amount:    r.amount,
				Currency:  r.currency,
				Available: r.amount >= 0,
				Services:  r.services,
				Estimate:  r.estimate,
				Note:      r.note,
			})
		}
		return emitJSON(rows)
	}

	scope := "Dispatcher-tagged spend"
	if billFlags.all {
		scope = "Total spend (all services)"
	}
	bold.Fprintf(os.Stdout, "%s, %s – %s (UTC)\n\n", scope,
		monthStart.Format("2006-01-02"), now.Format("2006-01-02"))

	for _, r := range results {
		fmt.Fprintf(os.Stdout, "%-10s ", r.provider)
		if r.amount < 0 {
			red.Fprintf(os.Stdout, "unavailable")
			fmt.Fprintf(os.Stdout, "  — %s\n", r.note)
			continue
		}
		green.Fprintf(os.Stdout, "%-8s %s", formatCost(r.amount), r.currency)
		if billFlags.reconcile && r.estimate >= 0 {
			delta := r.amount - r.estimate
			dim.Fprintf(os.Stdout, "   (est %s, Δ %+.2f)", formatCost(r.estimate), delta)
			if delta > 0.01 {
				red.Fprintf(os.Stdout, " ⚠ possible untracked spend")
			}
		}
		if r.note != "" {
			dim.Fprintf(os.Stdout, "  (%s)", r.note)
		}
		fmt.Fprintln(os.Stdout)
		if billFlags.byService {
			for _, s := range r.services {
				dim.Fprintf(os.Stdout, "             %-45s %s %s\n", s.Name, formatCost(s.Amount), r.currency)
			}
		}
	}
	return nil
}

// providerTargetID maps a bill provider name to its dispatcher target id, so
// --reconcile can look up dispatcher's tracked estimate for that provider.
func providerTargetID(provider string) string { return provider + "-vm" }

// addEstimates populates each provider's dispatcher-tracked estimate (sum of
// per-run cost estimates this month) so the caller can compare it to the bill.
func addEstimates(results []providerSpend, since time.Time) {
	hist, err := cost.NewHistoryStore()
	for i := range results {
		results[i].estimate = -1
		if err != nil {
			continue
		}
		total, _ := hist.SpendSince(providerTargetID(results[i].provider), since)
		results[i].estimate = total
	}
}

// awsBillArgs builds the `aws ce get-cost-and-usage` argv. Without all, it
// filters to dispatcher-tagged resources; with byService it groups by SERVICE.
func awsBillArgs(start, end time.Time, all, byService bool) []string {
	args := []string{"ce", "get-cost-and-usage",
		"--time-period", fmt.Sprintf("Start=%s,End=%s", start.Format("2006-01-02"), end.Format("2006-01-02")),
		"--granularity", "MONTHLY",
		"--metrics", "UnblendedCost",
		"--output", "json",
	}
	if !all {
		args = append(args, "--filter", `{"Tags":{"Key":"dispatcher","Values":["true"]}}`)
	}
	if byService {
		args = append(args, "--group-by", "Type=DIMENSION,Key=SERVICE")
	}
	return args
}

// parseAWSCost reads a Cost Explorer response. With byService it returns the
// per-service breakdown (and their sum); otherwise the period total.
func parseAWSCost(raw []byte, byService bool) (float64, string, []serviceSpend, error) {
	var parsed struct {
		ResultsByTime []struct {
			Total struct {
				UnblendedCost struct {
					Amount string `json:"Amount"`
					Unit   string `json:"Unit"`
				} `json:"UnblendedCost"`
			} `json:"Total"`
			Groups []struct {
				Keys    []string `json:"Keys"`
				Metrics struct {
					UnblendedCost struct {
						Amount string `json:"Amount"`
						Unit   string `json:"Unit"`
					} `json:"UnblendedCost"`
				} `json:"Metrics"`
			} `json:"Groups"`
		} `json:"ResultsByTime"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return 0, "", nil, err
	}
	var total float64
	currency := "USD"
	var services []serviceSpend
	for _, r := range parsed.ResultsByTime {
		if byService {
			for _, g := range r.Groups {
				v, err := strconv.ParseFloat(g.Metrics.UnblendedCost.Amount, 64)
				if err != nil {
					continue
				}
				name := ""
				if len(g.Keys) > 0 {
					name = g.Keys[0]
				}
				total += v
				if u := g.Metrics.UnblendedCost.Unit; u != "" {
					currency = u
				}
				if v > 0 {
					services = append(services, serviceSpend{Name: name, Amount: v})
				}
			}
			continue
		}
		v, err := strconv.ParseFloat(r.Total.UnblendedCost.Amount, 64)
		if err != nil {
			continue
		}
		total += v
		if u := r.Total.UnblendedCost.Unit; u != "" {
			currency = u
		}
	}
	sortServices(services)
	return total, currency, services, nil
}

// awsSpend uses Cost Explorer (needs ce:GetCostAndUsage). Data lags up to ~24h
// after Cost Explorer is first enabled.
func awsSpend(ctx context.Context, start, end time.Time, all, byService bool) providerSpend {
	out := providerSpend{provider: "aws", currency: "USD", estimate: -1}
	if _, err := billLookPath("aws"); err != nil {
		return unavailable(out, "aws CLI not installed")
	}
	if _, err := billExec(ctx, "aws", "sts", "get-caller-identity"); err != nil {
		return unavailable(out, "aws not authenticated (`aws configure`/`aws login`)")
	}
	raw, err := billExec(ctx, "aws", awsBillArgs(start, end, all, byService)...)
	if err != nil {
		return unavailable(out, fmt.Sprintf("Cost Explorer query failed (need ce:GetCostAndUsage; data lags ~24h after enabling): %v", trimCmdErr(err)))
	}
	amount, currency, services, err := parseAWSCost(raw, byService)
	if err != nil {
		return unavailable(out, fmt.Sprintf("parse aws output: %v", err))
	}
	out.amount, out.currency, out.services = amount, currency, services
	return out
}

// parseAzureCost reads `az consumption usage list`. Without all it keeps only
// dispatcher-tagged rows; with byService it aggregates by consumedService.
func parseAzureCost(raw []byte, all, byService bool) (float64, string, []serviceSpend, error) {
	var rows []struct {
		PretaxCost      string            `json:"pretaxCost"`
		Currency        string            `json:"currency"`
		ConsumedService string            `json:"consumedService"`
		Tags            map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return 0, "", nil, err
	}
	var total float64
	currency := "USD"
	byName := map[string]float64{}
	for _, r := range rows {
		if !all && r.Tags["dispatcher"] != "true" {
			continue
		}
		v, err := strconv.ParseFloat(r.PretaxCost, 64)
		if err != nil {
			continue
		}
		total += v
		if r.Currency != "" {
			currency = r.Currency
		}
		byName[r.ConsumedService] += v
	}
	var services []serviceSpend
	if byService {
		for name, amt := range byName {
			if amt > 0 {
				services = append(services, serviceSpend{Name: name, Amount: amt})
			}
		}
		sortServices(services)
	}
	return total, currency, services, nil
}

func azureSpend(ctx context.Context, start, end time.Time, all, byService bool) providerSpend {
	out := providerSpend{provider: "azure", currency: "USD", estimate: -1}
	if _, err := billLookPath("az"); err != nil {
		return unavailable(out, "az CLI not installed")
	}
	if _, err := billExec(ctx, "az", "account", "show"); err != nil {
		return unavailable(out, "az not authenticated (`az login`)")
	}
	raw, err := billExec(ctx, "az", "consumption", "usage", "list",
		"--start-date", start.Format("2006-01-02"),
		"--end-date", end.Format("2006-01-02"),
		"--output", "json")
	if err != nil {
		return unavailable(out, fmt.Sprintf("consumption query failed (need Billing Reader role): %v", trimCmdErr(err)))
	}
	amount, currency, services, err := parseAzureCost(raw, all, byService)
	if err != nil {
		return unavailable(out, fmt.Sprintf("parse az output: %v", err))
	}
	out.amount, out.currency, out.services = amount, currency, services
	return out
}

// gcpBillingTablePattern matches a fully-qualified BigQuery table:
// project.dataset.table. Projects may contain hyphens; datasets and tables are
// word characters. Anything else (backticks, quotes, whitespace, punctuation)
// is rejected so the value can't break out of the SQL identifier quoting.
var gcpBillingTablePattern = regexp.MustCompile(`^[A-Za-z0-9-]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+$`)

func validGCPBillingTable(table string) bool {
	return gcpBillingTablePattern.MatchString(table)
}

// buildGCPBillingSQL builds a BigQuery query over the billing-export table.
// Net cost = cost + credits. Without all, it filters to resources labeled
// dispatcher=true; with byService it groups by service.description.
func buildGCPBillingSQL(table string, start, end time.Time, all, byService bool) string {
	selectCols := "SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS net, currency"
	groupBy := "GROUP BY currency"
	if byService {
		selectCols = "service.description AS service, " + selectCols
		groupBy = "GROUP BY service.description, currency"
	}
	where := fmt.Sprintf("usage_start_time >= TIMESTAMP('%s') AND usage_start_time < TIMESTAMP('%s')",
		start.Format("2006-01-02"), end.Format("2006-01-02"))
	if !all {
		where += " AND EXISTS (SELECT 1 FROM UNNEST(labels) l WHERE l.key = 'dispatcher' AND l.value = 'true')"
	}
	return fmt.Sprintf("SELECT %s FROM `%s` WHERE %s %s", selectCols, table, where, groupBy)
}

// parseGCPBillingRows reads `bq query --format=json` rows (net, currency, and
// optionally service).
func parseGCPBillingRows(raw []byte) (float64, string, []serviceSpend, error) {
	var rows []struct {
		Service  string `json:"service"`
		Net      string `json:"net"`
		Currency string `json:"currency"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return 0, "", nil, err
	}
	var total float64
	currency := "USD"
	var services []serviceSpend
	for _, r := range rows {
		v, err := strconv.ParseFloat(r.Net, 64)
		if err != nil {
			continue
		}
		total += v
		if r.Currency != "" {
			currency = r.Currency
		}
		if r.Service != "" && v > 0 {
			services = append(services, serviceSpend{Name: r.Service, Amount: v})
		}
	}
	sortServices(services)
	return total, currency, services, nil
}

// gcpSpend queries the BigQuery billing export named by
// DISPATCHER_GCP_BILLING_TABLE (project.dataset.table). GCP has no direct
// billing CLI, so without that table there is nothing to query.
func gcpSpend(ctx context.Context, start, end time.Time, all, byService bool) providerSpend {
	out := providerSpend{provider: "gcp", currency: "USD", estimate: -1}
	table := os.Getenv("DISPATCHER_GCP_BILLING_TABLE")
	if table == "" {
		return unavailable(out, "set DISPATCHER_GCP_BILLING_TABLE=project.dataset.gcp_billing_export_v1_XXXX (from your BigQuery billing export)")
	}
	// The table name is interpolated into the BigQuery SQL, so validate it as a
	// strict fully-qualified identifier before use — a backtick would otherwise
	// escape the identifier quoting and inject arbitrary SQL run with the
	// caller's BigQuery credentials.
	if !validGCPBillingTable(table) {
		return unavailable(out, "DISPATCHER_GCP_BILLING_TABLE must be a plain project.dataset.table identifier (letters, digits, _ and - only)")
	}
	if _, err := billLookPath("bq"); err != nil {
		return unavailable(out, "bq CLI not installed (ships with the gcloud SDK)")
	}
	raw, err := billExec(ctx, "bq", "query", "--use_legacy_sql=false", "--format=json",
		buildGCPBillingSQL(table, start, end, all, byService))
	if err != nil {
		return unavailable(out, fmt.Sprintf("bq query failed (table may not have ingested data yet, ~hours after enabling): %v", trimCmdErr(err)))
	}
	amount, currency, services, err := parseGCPBillingRows(raw)
	if err != nil {
		return unavailable(out, fmt.Sprintf("parse bq output: %v", err))
	}
	out.amount, out.currency, out.services = amount, currency, services
	return out
}

// hetznerSpend: hcloud has no billing endpoint, so fall back to dispatcher's own
// per-run sampling. The authoritative invoice lives in the Hetzner console.
func hetznerSpend(monthStart time.Time) providerSpend {
	out := providerSpend{provider: "hetzner", currency: "USD", estimate: -1}
	hist, err := cost.NewHistoryStore()
	if err != nil {
		return unavailable(out, fmt.Sprintf("history unavailable: %v", err))
	}
	total, n := hist.SpendSince("hetzner-vm", monthStart)
	out.amount = total
	out.note = fmt.Sprintf("no billing API; dispatcher-tracked estimate over %d run(s); authoritative: https://console.hetzner.cloud/", n)
	return out
}

func unavailable(p providerSpend, note string) providerSpend {
	p.amount = -1
	p.note = note
	return p
}

func sortServices(s []serviceSpend) {
	sort.Slice(s, func(i, j int) bool { return s[i].Amount > s[j].Amount })
}

// trimCmdErr trims the noisy stderr-in-error-message that exec.ExitError
// produces, keeping just the exit-code summary.
func trimCmdErr(err error) error {
	if ee, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("exit %d", ee.ExitCode())
	}
	return err
}
