package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// AWSBulkPriceListBaseURL is AWS's public, unauthenticated Bulk Price List API.
// Documented at:
//
//	https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/price-changes.html
//
// Per-region files live under .../offers/v1.0/aws/AmazonEC2/current/<region>/index.json
// and contain every EC2 product+term currently sold in that region. The file
// is large (10–30 MB) but stable, cacheable, and the same data AWS uses for its
// own pricing pages.
const AWSBulkPriceListBaseURL = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/current"

// AWSFetcher pulls EC2 on-demand pricing from AWS's public Bulk Price List API.
// No credentials required — this is the same data backing console.aws.amazon.com
// pricing pages.
type AWSFetcher struct {
	Region string // e.g. "us-east-1"

	// Client overrides the HTTP client for tests.
	Client *http.Client
	// BaseURL overrides the bulk price list root for tests.
	BaseURL string
}

func NewAWSFetcher(region string) *AWSFetcher {
	if region == "" {
		region = "us-east-1"
	}
	return &AWSFetcher{Region: region}
}

func (a *AWSFetcher) Provider() ProviderID { return ProviderAWS }

func (a *AWSFetcher) Fetch(ctx context.Context) ([]InstanceType, error) {
	client := a.Client
	if client == nil {
		client = http.DefaultClient
	}
	base := a.BaseURL
	if base == "" {
		base = AWSBulkPriceListBaseURL
	}

	url := fmt.Sprintf("%s/%s/index.json", base, a.Region)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build aws price list request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aws price list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("aws price list status %d for %s: %s", resp.StatusCode, a.Region, body)
	}

	return parseAWSBulkPriceList(resp.Body)
}

// awsBulkPriceList is the shape of the per-region Bulk Price List doc.
// We only read the OnDemand terms — Reserved/SavingsPlans aren't useful for
// estimating what an on-demand launch would cost.
type awsBulkPriceList struct {
	Products map[string]struct {
		SKU           string            `json:"sku"`
		ProductFamily string            `json:"productFamily"`
		Attributes    map[string]string `json:"attributes"`
	} `json:"products"`
	Terms struct {
		OnDemand map[string]map[string]struct {
			PriceDimensions map[string]struct {
				Unit         string            `json:"unit"`
				PricePerUnit map[string]string `json:"pricePerUnit"`
			} `json:"priceDimensions"`
		} `json:"OnDemand"`
	} `json:"terms"`
}

func parseAWSBulkPriceList(r io.Reader) ([]InstanceType, error) {
	var doc awsBulkPriceList
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse aws price list: %w", err)
	}

	var instances []InstanceType
	for sku, product := range doc.Products {
		if product.ProductFamily != "Compute Instance" {
			continue
		}
		// Filter to the canonical "what you'd actually pay" SKU:
		// Linux, shared tenancy, no pre-installed software, used capacity.
		attrs := product.Attributes
		if attrs["operatingSystem"] != "Linux" ||
			attrs["tenancy"] != "Shared" ||
			attrs["preInstalledSw"] != "NA" ||
			attrs["capacityStatus"] != "Used" {
			continue
		}

		name := attrs["instanceType"]
		if name == "" {
			continue
		}

		price, ok := extractAWSBulkPrice(doc, sku)
		if !ok || price <= 0 {
			continue
		}
		// Sanity bounds: reject prices that fall outside the band of any
		// real EC2 instance. Defense against a poisoned bulk-JSON response
		// (DNS hijack, compromised mirror) injecting a near-zero price that
		// would cause the planner to recommend a runaway-cost target. Today
		// the cheapest real EC2 instance is $0.0042/hr and the most
		// expensive on-demand SKU is ~$80/hr.
		if !isPlausibleHourlyPrice(price) {
			continue
		}

		vcpus, _ := strconv.Atoi(attrs["vcpu"])
		gpuCount, _ := strconv.Atoi(attrs["gpu"])
		instances = append(instances, InstanceType{
			Name:         name,
			Provider:     ProviderAWS,
			VCPUs:        vcpus,
			MemoryGB:     parseAWSMemoryGB(attrs["memory"]),
			PricePerHour: price,
			Arch:         normalizeAWSArch(attrs["physicalProcessor"], attrs["instanceFamily"]),
			GPUCount:     gpuCount,
			GPUModel:     normalizeAWSGPUModel(attrs["gpuMemory"], name),
		})
	}
	return instances, nil
}

// extractAWSBulkPrice walks the nested terms.OnDemand[SKU] → priceDimensions
// structure to find the hourly USD rate. Returns (0, false) if no Hrs
// dimension exists for the SKU.
func extractAWSBulkPrice(doc awsBulkPriceList, sku string) (float64, bool) {
	offers, ok := doc.Terms.OnDemand[sku]
	if !ok {
		return 0, false
	}
	for _, offer := range offers {
		for _, dim := range offer.PriceDimensions {
			if dim.Unit != "Hrs" && !strings.HasPrefix(dim.Unit, "Hrs") {
				continue
			}
			usd, ok := dim.PricePerUnit["USD"]
			if !ok {
				continue
			}
			v, err := strconv.ParseFloat(usd, 64)
			if err != nil {
				continue
			}
			return v, true
		}
	}
	return 0, false
}

// isPlausibleHourlyPrice rejects on-demand hourly prices outside the band any
// real cloud VM falls into. Used to bound damage from a poisoned pricing
// response. Bounds chosen so legit micro instances (~$0.004/hr) and
// high-end H100 boxes (~$80/hr) both pass.
func isPlausibleHourlyPrice(p float64) bool {
	const min, max = 0.001, 200.0
	return p >= min && p <= max
}

// parseAWSMemoryGB extracts the numeric GB value from AWS's "16 GiB" format.
// Returns 0 for unparseable strings.
func parseAWSMemoryGB(s string) float64 {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " "); i > 0 {
		s = s[:i]
	}
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// normalizeAWSArch derives x86_64 vs arm64 from AWS's loose attribute strings.
// Graviton instances (a1, t4g, m6g, c6g, r6g, etc.) are arm64.
func normalizeAWSArch(processor, family string) string {
	if strings.Contains(strings.ToLower(processor), "graviton") {
		return "arm64"
	}
	return "x86_64"
}

// normalizeAWSGPUModel maps instance-family naming to GPU model strings the
// catalog uses (e.g. "t4", "a100", "h100"). gpuMemory attribute is present but
// the family name is the cleanest signal.
func normalizeAWSGPUModel(_ string, instanceName string) string {
	n := strings.ToLower(instanceName)
	switch {
	case strings.HasPrefix(n, "g4dn"), strings.HasPrefix(n, "g4ad"):
		return "t4"
	case strings.HasPrefix(n, "g5"):
		return "a10g"
	case strings.HasPrefix(n, "p3"):
		return "v100"
	case strings.HasPrefix(n, "p4d"), strings.HasPrefix(n, "p4de"):
		return "a100"
	case strings.HasPrefix(n, "p5"):
		return "h100"
	}
	return ""
}
