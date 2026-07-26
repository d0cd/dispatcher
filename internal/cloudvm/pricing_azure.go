package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AzureRetailPricesURL is the public, unauthenticated endpoint for Azure VM
// retail pricing. Documented at:
//
//	https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices
const AzureRetailPricesURL = "https://prices.azure.com/api/retail/prices"

// AzureFetcher pulls VM pricing from the public Azure Retail Prices API.
// No credentials required — Azure publishes this for everyone.
type AzureFetcher struct {
	// Region scopes the fetch to a single armRegionName. Empty means "eastus".
	Region string

	// Client overrides the HTTP client for tests.
	Client *http.Client

	// BaseURL overrides the endpoint for tests.
	BaseURL string
}

func NewAzureFetcher(region string) *AzureFetcher {
	if region == "" {
		region = "eastus"
	}
	return &AzureFetcher{Region: region}
}

func (a *AzureFetcher) Provider() ProviderID { return ProviderAzure }

func (a *AzureFetcher) Fetch(ctx context.Context) ([]InstanceType, error) {
	client := a.Client
	if client == nil {
		client = http.DefaultClient
	}
	base := a.BaseURL
	if base == "" {
		base = AzureRetailPricesURL
	}

	// Filter to Virtual Machines, Consumption (not reservations), our region. The
	// response includes both on-demand and Spot meters for a SKU; we keep on-demand
	// as the price and fold the Spot meter into that SKU's SpotPricePerHour.
	filter := fmt.Sprintf(
		"serviceName eq 'Virtual Machines' and priceType eq 'Consumption' and armRegionName eq '%s'",
		a.Region,
	)
	q := url.Values{}
	q.Set("$filter", filter)
	q.Set("currencyCode", "USD")

	var (
		instances []InstanceType
		spot      = map[string]float64{} // SKU → cheapest live Spot price
		next      = base + "?" + q.Encode()
	)

	// Retail Prices paginates with NextPageLink. Cap iterations defensively to
	// avoid runaway loops if the API misbehaves.
	for i := 0; i < 50 && next != ""; i++ {
		page, pageSpot, link, err := fetchAzurePage(ctx, client, next)
		if err != nil {
			return nil, err
		}
		instances = append(instances, page...)
		for sku, price := range pageSpot {
			if cur, ok := spot[sku]; !ok || price < cur {
				spot[sku] = price
			}
		}
		next = link
	}

	// Fold the live Spot price onto each SKU so ApplySpot uses the real ratio
	// (Azure Spot commonly runs far below the coarse per-provider fallback factor)
	// instead of a pessimistic estimate — but only when it's genuinely cheaper than
	// on-demand.
	for i := range instances {
		if sp, ok := spot[instances[i].Name]; ok && sp > 0 && sp < instances[i].PricePerHour {
			instances[i].SpotPricePerHour = sp
		}
	}

	return instances, nil
}

func fetchAzurePage(ctx context.Context, client *http.Client, u string) ([]InstanceType, map[string]float64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, "", fmt.Errorf("build azure request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("azure retail prices: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, nil, "", fmt.Errorf("azure retail prices status %d: %s", resp.StatusCode, body)
	}

	var body struct {
		Items        []azureRetailItem `json:"Items"`
		NextPageLink string            `json:"NextPageLink"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, nil, "", fmt.Errorf("parse azure retail prices: %w", err)
	}

	var instances []InstanceType
	spot := map[string]float64{}
	for _, item := range body.Items {
		inst, isSpot, ok := azureItemToInstance(item)
		if !ok {
			continue
		}
		if isSpot {
			if cur, exists := spot[inst.Name]; !exists || inst.PricePerHour < cur {
				spot[inst.Name] = inst.PricePerHour
			}
			continue
		}
		instances = append(instances, inst)
	}
	return instances, spot, body.NextPageLink, nil
}

// azureRetailItem represents one Azure Retail Prices entry.
type azureRetailItem struct {
	ArmSkuName     string  `json:"armSkuName"`
	RetailPrice    float64 `json:"retailPrice"`
	ProductName    string  `json:"productName"`
	MeterName      string  `json:"meterName"`
	UnitOfMeasure  string  `json:"unitOfMeasure"`
	Type           string  `json:"type"`
	IsPrimaryMeter bool    `json:"isPrimaryMeterRegion"`
}

// azureItemToInstance converts a retail-price row into an InstanceType. Azure's
// Retail Prices API does not return vCPU/memory per SKU (those live in a
// separate compute SKUs API we don't query), so VCPUs/MemoryGB are left zero.
// Catalog.FindCheapest treats a zero spec as "unknown" and skips the
// size filters rather than discarding the row. Items we can't map cleanly are
// dropped. isSpot reports whether the row is a Spot meter; the caller folds its
// price into the matching on-demand SKU's SpotPricePerHour (for a Spot row,
// PricePerHour carries the spot rate) rather than emitting it as its own instance.
func azureItemToInstance(item azureRetailItem) (inst InstanceType, isSpot, ok bool) {
	// Reject implausible prices for the same reason AWS does: a poisoned or
	// hijacked pricing response with a near-zero rate would steer the planner
	// (which sorts ascending and gates on the estimate) onto a runaway-cost
	// target. See isPlausibleHourlyPrice.
	if item.ArmSkuName == "" || !isPlausibleHourlyPrice(item.RetailPrice) {
		return InstanceType{}, false, false
	}
	if strings.Contains(item.ProductName, "Windows") {
		return InstanceType{}, false, false
	}
	// Unit "1 Hour" → hourly price; skip anything we don't recognize as hourly.
	if !strings.HasPrefix(item.UnitOfMeasure, "1 Hour") {
		return InstanceType{}, false, false
	}
	// "Low Priority" is the deprecated interruptible tier; ignore it in favor of
	// the current "Spot" meter so a stale legacy rate can't shadow live spot.
	if strings.Contains(item.MeterName, "Low Priority") {
		return InstanceType{}, false, false
	}

	inst = InstanceType{
		Name:         item.ArmSkuName,
		Provider:     ProviderAzure,
		PricePerHour: item.RetailPrice,
		Arch:         "x86_64",
	}
	return inst, strings.Contains(item.MeterName, "Spot"), true
}
