package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var billCmd = &cobra.Command{
	Use:   "bill",
	Short: "Show dispatcher-tagged spend month-to-date across configured clouds",
	Long: `Queries each cloud provider's billing API for resources tagged
'dispatcher=true' in the current calendar month.

For each provider, the command checks:
  1. Is the provider CLI installed?
  2. Is it authenticated?
  3. Does the caller have billing-read permission?

Providers where any of those fails are reported clearly and skipped.

Note: dispatcher's own per-run cost tracking (see 'dispatcher list',
'dispatcher cost <id>') uses sampled runtime and may drift 5-15% from
the authoritative provider totals shown here.`,
	RunE: runBill,
}

func init() {
	rootCmd.AddCommand(billCmd)
}

type providerSpend struct {
	provider string
	amount   float64 // -1 means unavailable
	currency string
	note     string // populated when unavailable or with a caveat
}

func runBill(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)

	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)

	bold.Fprintf(os.Stdout, "Dispatcher-tagged spend, %s – %s (UTC)\n\n",
		monthStart.Format("2006-01-02"), now.Format("2006-01-02"))

	results := []providerSpend{
		awsSpend(ctx, monthStart, monthEnd),
		azureSpend(ctx, monthStart, monthEnd),
		gcpSpend(),
		hetznerSpend(),
	}

	for _, r := range results {
		fmt.Fprintf(os.Stdout, "%-10s ", r.provider)
		switch {
		case r.amount >= 0:
			green.Fprintf(os.Stdout, "%6.2f %s", r.amount, r.currency)
			if r.note != "" {
				dim.Fprintf(os.Stdout, "  (%s)", r.note)
			}
			fmt.Fprintln(os.Stdout)
		default:
			red.Fprintf(os.Stdout, "unavailable")
			fmt.Fprintf(os.Stdout, "  — %s\n", r.note)
		}
	}
	return nil
}

// awsSpend uses Cost Explorer. Requires the `aws` CLI, valid credentials,
// and the `ce:GetCostAndUsage` permission on the caller's IAM principal.
func awsSpend(ctx context.Context, start, end time.Time) providerSpend {
	out := providerSpend{provider: "aws"}
	if _, err := exec.LookPath("aws"); err != nil {
		out.note = "aws CLI not installed"
		out.amount = -1
		return out
	}
	if err := exec.CommandContext(ctx, "aws", "sts", "get-caller-identity").Run(); err != nil {
		out.note = "aws not authenticated (`aws configure` or set AWS_PROFILE)"
		out.amount = -1
		return out
	}
	cmd := exec.CommandContext(ctx, "aws", "ce", "get-cost-and-usage",
		"--time-period", fmt.Sprintf("Start=%s,End=%s",
			start.Format("2006-01-02"), end.Format("2006-01-02")),
		"--granularity", "MONTHLY",
		"--metrics", "UnblendedCost",
		"--filter", `{"Tags":{"Key":"dispatcher","Values":["true"]}}`,
		"--output", "json",
	)
	raw, err := cmd.Output()
	if err != nil {
		out.note = fmt.Sprintf("Cost Explorer query failed (need ce:GetCostAndUsage IAM): %v", trimCmdErr(err))
		out.amount = -1
		return out
	}
	var parsed struct {
		ResultsByTime []struct {
			Total struct {
				UnblendedCost struct {
					Amount string `json:"Amount"`
					Unit   string `json:"Unit"`
				} `json:"UnblendedCost"`
			} `json:"Total"`
		} `json:"ResultsByTime"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		out.note = fmt.Sprintf("parse aws output: %v", err)
		out.amount = -1
		return out
	}
	var total float64
	out.currency = "USD"
	for _, r := range parsed.ResultsByTime {
		v, _ := strconv.ParseFloat(r.Total.UnblendedCost.Amount, 64)
		total += v
		if r.Total.UnblendedCost.Unit != "" {
			out.currency = r.Total.UnblendedCost.Unit
		}
	}
	out.amount = total
	return out
}

// azureSpend uses `az consumption usage list`. The consumption namespace
// requires a billing-reader role; many subscription members don't have it.
func azureSpend(ctx context.Context, start, end time.Time) providerSpend {
	out := providerSpend{provider: "azure"}
	if _, err := exec.LookPath("az"); err != nil {
		out.note = "az CLI not installed"
		out.amount = -1
		return out
	}
	if err := exec.CommandContext(ctx, "az", "account", "show").Run(); err != nil {
		out.note = "az not authenticated (`az login`)"
		out.amount = -1
		return out
	}
	cmd := exec.CommandContext(ctx, "az", "consumption", "usage", "list",
		"--start-date", start.Format("2006-01-02"),
		"--end-date", end.Format("2006-01-02"),
		"--output", "json",
	)
	raw, err := cmd.Output()
	if err != nil {
		out.note = fmt.Sprintf("consumption query failed (need Billing Reader role): %v", trimCmdErr(err))
		out.amount = -1
		return out
	}
	var rows []struct {
		PretaxCost string            `json:"pretaxCost"`
		Currency   string            `json:"currency"`
		Tags       map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		out.note = fmt.Sprintf("parse az output: %v", err)
		out.amount = -1
		return out
	}
	var total float64
	out.currency = "USD"
	for _, r := range rows {
		if r.Tags["dispatcher"] != "true" {
			continue
		}
		v, _ := strconv.ParseFloat(r.PretaxCost, 64)
		total += v
		if r.Currency != "" {
			out.currency = r.Currency
		}
	}
	out.amount = total
	return out
}

// gcpSpend cannot be queried via gcloud directly — GCP billing data lives
// in a BigQuery export the user must enable. Tell them so plainly.
func gcpSpend() providerSpend {
	return providerSpend{
		provider: "gcp",
		amount:   -1,
		note:     "no direct CLI; enable billing-data export to BigQuery, then query the `gcp_billing_export_v1_*` table",
	}
}

// hetznerSpend: hcloud has no billing endpoint. The current invoice lives
// in https://accounts.hetzner.com/.
func hetznerSpend() providerSpend {
	return providerSpend{
		provider: "hetzner",
		amount:   -1,
		note:     "no billing API; see https://accounts.hetzner.com/",
	}
}

// trimCmdErr trims the noisy stderr-in-error-message that exec.ExitError
// produces, keeping just the exit-code summary.
func trimCmdErr(err error) error {
	if ee, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("exit %d", ee.ExitCode())
	}
	return err
}
