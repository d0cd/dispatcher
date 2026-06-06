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

	// Filter to Virtual Machines, Linux, Consumption (not reservations), our region.
	// We exclude "Low Priority" and "Spot" so the catalog represents standard pricing.
	filter := fmt.Sprintf(
		"serviceName eq 'Virtual Machines' and priceType eq 'Consumption' and armRegionName eq '%s'",
		a.Region,
	)
	q := url.Values{}
	q.Set("$filter", filter)
	q.Set("currencyCode", "USD")

	var (
		instances []InstanceType
		next      = base + "?" + q.Encode()
	)

	// Retail Prices paginates with NextPageLink. Cap iterations defensively to
	// avoid runaway loops if the API misbehaves.
	for i := 0; i < 50 && next != ""; i++ {
		page, link, err := fetchAzurePage(ctx, client, next)
		if err != nil {
			return nil, err
		}
		instances = append(instances, page...)
		next = link
	}

	return instances, nil
}

func fetchAzurePage(ctx context.Context, client *http.Client, u string) ([]InstanceType, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build azure request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("azure retail prices: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", fmt.Errorf("azure retail prices status %d: %s", resp.StatusCode, body)
	}

	var body struct {
		Items        []azureRetailItem `json:"Items"`
		NextPageLink string            `json:"NextPageLink"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, "", fmt.Errorf("parse azure retail prices: %w", err)
	}

	var instances []InstanceType
	for _, item := range body.Items {
		inst, ok := azureItemToInstance(item)
		if !ok {
			continue
		}
		instances = append(instances, inst)
	}
	return instances, body.NextPageLink, nil
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
// API doesn't return vCPU/memory per SKU — those come from a separate compute
// SKUs API. For the catalog we surface SKU name + price; vCPU/memory are filled
// in later from the static lookup. Items we can't map cleanly are dropped.
func azureItemToInstance(item azureRetailItem) (InstanceType, bool) {
	if item.ArmSkuName == "" || item.RetailPrice <= 0 {
		return InstanceType{}, false
	}
	// Skip low-priority/spot meters and Windows VMs (we only run Linux workloads).
	if strings.Contains(item.MeterName, "Low Priority") || strings.Contains(item.MeterName, "Spot") {
		return InstanceType{}, false
	}
	if strings.Contains(item.ProductName, "Windows") {
		return InstanceType{}, false
	}
	// Unit "1 Hour" → hourly price; skip anything we don't recognize as hourly.
	if !strings.HasPrefix(item.UnitOfMeasure, "1 Hour") {
		return InstanceType{}, false
	}

	return InstanceType{
		Name:         item.ArmSkuName,
		Provider:     ProviderAzure,
		PricePerHour: item.RetailPrice,
		Arch:         "x86_64",
	}, true
}
