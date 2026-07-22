package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// awsPricingEndpointRegion is where the AWS Price List Query API is served.
// It's only available from a couple of endpoints regardless of which region is
// being priced — the priced region is a filter (regionCode), not the endpoint.
const awsPricingEndpointRegion = "us-east-1"

// awsPricingMaxPages bounds pagination at 100 SKUs/page. A single region's
// Linux/shared/on-demand compute catalog is a few hundred SKUs, well under this;
// the cap is a runaway backstop, not an expected limit.
const awsPricingMaxPages = 40

// AWSFetcher pulls EC2 on-demand pricing from the AWS Price List Query API via
// `aws pricing get-products`, filtered to the region's Linux/shared/on-demand
// compute SKUs. This replaces the per-region Bulk Price List file (~480 MB,
// because it bundles every Reserved/Savings-Plan term), which rarely downloads
// and parses inside a plan's deadline. Unlike the other fetchers it needs AWS
// credentials + the pricing:GetProducts permission; when the CLI is missing or
// unauthenticated the Fetch errors and the catalog records it as skipped.
type AWSFetcher struct {
	Region string // region to price, e.g. "us-west-2" (a filter, not the endpoint)
}

func NewAWSFetcher(region string) *AWSFetcher {
	if region == "" {
		region = "us-east-1"
	}
	return &AWSFetcher{Region: region}
}

func (a *AWSFetcher) Provider() ProviderID { return ProviderAWS }

func (a *AWSFetcher) Fetch(ctx context.Context) ([]InstanceType, error) {
	// Exact-match filters so the API returns only the "what you'd actually pay"
	// SKU: Linux, shared tenancy, no pre-installed software, used capacity.
	filters := []string{
		"Type=TERM_MATCH,Field=regionCode,Value=" + a.Region,
		"Type=TERM_MATCH,Field=operatingSystem,Value=Linux",
		"Type=TERM_MATCH,Field=tenancy,Value=Shared",
		"Type=TERM_MATCH,Field=capacitystatus,Value=Used",
		"Type=TERM_MATCH,Field=preInstalledSw,Value=NA",
	}

	var instances []InstanceType
	token := ""
	for page := 0; page < awsPricingMaxPages; page++ {
		args := []string{
			"pricing", "get-products",
			"--service-code", "AmazonEC2",
			"--region", awsPricingEndpointRegion,
			"--max-results", "100",
			"--output", "json",
			"--filters",
		}
		args = append(args, filters...)
		if token != "" {
			args = append(args, "--next-token", token)
		}

		out, err := runCLI(ctx, "aws", args...)
		if err != nil {
			return nil, fmt.Errorf("aws pricing get-products: %w", err)
		}

		var resp struct {
			PriceList []string `json:"PriceList"`
			NextToken string   `json:"NextToken"`
		}
		if err := json.Unmarshal(out, &resp); err != nil {
			return nil, fmt.Errorf("parse aws pricing response: %w", err)
		}
		for _, entry := range resp.PriceList {
			if inst, ok := parseAWSPriceListEntry(entry); ok {
				instances = append(instances, inst)
			}
		}
		if resp.NextToken == "" {
			break
		}
		token = resp.NextToken
	}
	return instances, nil
}

// awsQueryProduct is one PriceList entry from the Query API (each is itself a
// JSON string). terms.OnDemand is keyed by offer term code directly — one level
// shallower than the Bulk Price List, which keys by SKU first.
type awsQueryProduct struct {
	Product struct {
		ProductFamily string            `json:"productFamily"`
		Attributes    map[string]string `json:"attributes"`
	} `json:"product"`
	Terms struct {
		OnDemand map[string]struct {
			PriceDimensions map[string]struct {
				Unit         string            `json:"unit"`
				PricePerUnit map[string]string `json:"pricePerUnit"`
			} `json:"priceDimensions"`
		} `json:"OnDemand"`
	} `json:"terms"`
}

// parseAWSPriceListEntry turns one get-products PriceList entry into an
// InstanceType. Returns (_, false) for non-compute products or entries without a
// plausible hourly on-demand price.
func parseAWSPriceListEntry(entry string) (InstanceType, bool) {
	var p awsQueryProduct
	if err := json.Unmarshal([]byte(entry), &p); err != nil {
		return InstanceType{}, false
	}
	if p.Product.ProductFamily != "Compute Instance" {
		return InstanceType{}, false
	}
	attrs := p.Product.Attributes
	name := attrs["instanceType"]
	if name == "" {
		return InstanceType{}, false
	}

	price, ok := extractAWSOnDemandPrice(p)
	if !ok || price <= 0 {
		return InstanceType{}, false
	}
	// Sanity bounds: reject prices outside the band of any real EC2 instance —
	// defense against a poisoned response injecting a near-zero price that would
	// make the planner recommend a runaway-cost target.
	if !isPlausibleHourlyPrice(price) {
		return InstanceType{}, false
	}

	vcpus, _ := strconv.Atoi(attrs["vcpu"])
	gpuCount, _ := strconv.Atoi(attrs["gpu"])
	return InstanceType{
		Name:         name,
		Provider:     ProviderAWS,
		VCPUs:        vcpus,
		MemoryGB:     parseAWSMemoryGB(attrs["memory"]),
		PricePerHour: price,
		Arch:         normalizeAWSArch(attrs["physicalProcessor"], attrs["instanceFamily"]),
		GPUCount:     gpuCount,
		GPUModel:     normalizeAWSGPUModel(attrs["gpuMemory"], name),
	}, true
}

// extractAWSOnDemandPrice walks terms.OnDemand → priceDimensions for the hourly
// USD rate. Returns (0, false) if no Hrs dimension exists.
func extractAWSOnDemandPrice(p awsQueryProduct) (float64, bool) {
	for _, offer := range p.Terms.OnDemand {
		for _, dim := range offer.PriceDimensions {
			if dim.Unit != "Hrs" && !strings.HasPrefix(dim.Unit, "Hrs") {
				continue
			}
			usd, ok := dim.PricePerUnit["USD"]
			if !ok {
				continue
			}
			if v, err := strconv.ParseFloat(usd, 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// isPlausibleHourlyPrice rejects on-demand hourly prices outside the band any
// real cloud VM falls into. Used to bound damage from a poisoned pricing
// response. Bounds chosen so legit micro instances (~$0.004/hr) and high-end
// H100 boxes (~$80/hr) both pass.
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
// catalog uses (e.g. "t4", "a100", "h100").
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
