package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
)

// GCPComputeServiceID is the well-known Cloud Billing service ID for Compute
// Engine. Documented at https://cloud.google.com/billing/v1/how-tos/catalog-api.
const GCPComputeServiceID = "6F81-5844-456A"

// GCPFetcher pulls Compute Engine pricing from the Cloud Billing Catalog API.
// Authentication uses `gcloud auth print-access-token` so the user doesn't have
// to manage a separate API key.
//
// The catalog API returns SKUs (priced units) and the compute-types API
// returns machine specs (vCPU/memory). We join them on machine-type name.
type GCPFetcher struct {
	Region string // e.g. "us-central1"

	// Client overrides the HTTP client for tests.
	Client *http.Client
	// BaseURL overrides the billing catalog endpoint for tests.
	BaseURL string
	// Token, when set, replaces the gcloud-derived bearer token (test hook).
	Token string
	// MachineTypesJSON, when set, replaces the gcloud-derived machine-types
	// response (test hook).
	MachineTypesJSON []byte
}

func NewGCPFetcher(region string) *GCPFetcher {
	if region == "" {
		region = "us-central1"
	}
	return &GCPFetcher{Region: region}
}

func (g *GCPFetcher) Provider() ProviderID { return ProviderGCP }

func (g *GCPFetcher) Fetch(ctx context.Context) ([]InstanceType, error) {
	specs, err := g.fetchMachineSpecs(ctx)
	if err != nil {
		return nil, err
	}

	token := g.Token
	if token == "" {
		t, err := gcloudAccessToken(ctx)
		if err != nil {
			return nil, err
		}
		token = t
	}

	skus, err := g.fetchBillingSKUs(ctx, token)
	if err != nil {
		return nil, err
	}

	return joinGCPSpecsAndPrices(specs, skus, g.Region), nil
}

func (g *GCPFetcher) fetchMachineSpecs(ctx context.Context) ([]gcpMachineType, error) {
	if g.MachineTypesJSON != nil {
		return parseGCPMachineTypes(g.MachineTypesJSON)
	}
	if _, err := exec.LookPath("gcloud"); err != nil {
		return nil, fmt.Errorf("%w: gcloud CLI not found", ErrCredentialsMissing)
	}
	zone := g.Region + "-a"
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "machine-types", "list",
		"--zones", zone, "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		if isGcloudAuthErr(err) {
			return nil, ErrCredentialsMissing
		}
		return nil, fmt.Errorf("gcloud compute machine-types list: %w", err)
	}
	return parseGCPMachineTypes(out)
}

func gcloudAccessToken(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "gcloud", "auth", "print-access-token")
	out, err := cmd.Output()
	if err != nil {
		if isGcloudAuthErr(err) {
			return "", ErrCredentialsMissing
		}
		return "", fmt.Errorf("gcloud auth print-access-token: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (g *GCPFetcher) fetchBillingSKUs(ctx context.Context, token string) ([]gcpSKU, error) {
	client := g.Client
	if client == nil {
		client = http.DefaultClient
	}
	base := g.BaseURL
	if base == "" {
		base = "https://cloudbilling.googleapis.com/v1"
	}

	endpoint := fmt.Sprintf("%s/services/%s/skus", base, GCPComputeServiceID)
	q := url.Values{}
	q.Set("currencyCode", "USD")
	// The Compute Engine catalog is ~30k SKUs; 5000 (the API max page size)
	// keeps it to ~7 sequential pages instead of ~30.
	q.Set("pageSize", "5000")

	var (
		all       []gcpSKU
		pageToken string
	)
	for i := 0; i < 50; i++ {
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		page, next, err := gcpFetchSKUPage(ctx, client, endpoint+"?"+q.Encode(), token)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if next == "" {
			break
		}
		pageToken = next
	}
	return all, nil
}

func gcpFetchSKUPage(ctx context.Context, client *http.Client, u, token string) ([]gcpSKU, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build gcp request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("gcp billing catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", fmt.Errorf("%w: gcp billing catalog %d: %s", ErrCredentialsMissing, resp.StatusCode, body)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", fmt.Errorf("gcp billing catalog status %d: %s", resp.StatusCode, body)
	}

	var body struct {
		SKUs          []gcpSKU `json:"skus"`
		NextPageToken string   `json:"nextPageToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, "", fmt.Errorf("parse gcp catalog: %w", err)
	}
	return body.SKUs, body.NextPageToken, nil
}

// gcpMachineType is the subset of `gcloud compute machine-types list` we read.
type gcpMachineType struct {
	Name      string `json:"name"`
	GuestCpus int    `json:"guestCpus"`
	MemoryMb  int    `json:"memoryMb"`
}

func parseGCPMachineTypes(raw []byte) ([]gcpMachineType, error) {
	var types []gcpMachineType
	if err := json.Unmarshal(raw, &types); err != nil {
		return nil, fmt.Errorf("parse gcp machine types: %w", err)
	}
	return types, nil
}

// gcpSKU is the subset of a Cloud Billing Catalog SKU we read.
type gcpSKU struct {
	Description string `json:"description"`
	Category    struct {
		ResourceFamily string `json:"resourceFamily"`
		ResourceGroup  string `json:"resourceGroup"`
		UsageType      string `json:"usageType"`
	} `json:"category"`
	ServiceRegions []string `json:"serviceRegions"`
	PricingInfo    []struct {
		PricingExpression struct {
			TieredRates []struct {
				UnitPrice struct {
					Units string `json:"units"`
					Nanos int64  `json:"nanos"`
				} `json:"unitPrice"`
			} `json:"tieredRates"`
		} `json:"pricingExpression"`
	} `json:"pricingInfo"`
}

func (s gcpSKU) hourlyUSD() float64 {
	if len(s.PricingInfo) == 0 {
		return 0
	}
	rates := s.PricingInfo[0].PricingExpression.TieredRates
	if len(rates) == 0 {
		return 0
	}
	last := rates[len(rates)-1].UnitPrice
	units := 0.0
	if u := last.Units; u != "" {
		// Units is a string like "0"; we ignore the rare nonzero case.
		fmt.Sscanf(u, "%f", &units)
	}
	return units + float64(last.Nanos)/1e9
}

// gcpFamily describes how to match a GCP machine-type prefix to its Cloud
// Billing Catalog SKUs. Per-family because each family has its own CPU + RAM
// pricing (and, for accelerator families, GPU pricing).
type gcpFamily struct {
	prefix string // machine-type prefix, e.g. "n1-", "a2-highgpu-"
	// SKU description substrings (case-insensitive) — must hit a unique
	// Core/Ram SKU for the family.
	cpuSKU string
	ramSKU string
	// GPU info — empty for CPU-only families.
	gpuSKU   string
	gpuModel string
	// arch defaults to x86_64 when empty.
	arch string
}

// gcpFamilies is the curated catalog of GCP machine-type families we surface.
// Ordering matters: more specific prefixes must come before broader ones
// (e.g. "a2-megagpu-" before "a2-" if both were listed) so matchGCPFamily
// picks the right one. Today only "a3-megagpu-" vs "a3-highgpu-" need that
// careful ordering.
//
// SKU description substrings are picked from real Cloud Billing Catalog
// responses; they're stable but worth re-verifying when adding a new family.
var gcpFamilies = []gcpFamily{
	// General purpose
	{prefix: "e2-", cpuSKU: "e2 instance core", ramSKU: "e2 instance ram"},
	{prefix: "n2d-", cpuSKU: "n2d amd instance core", ramSKU: "n2d amd instance ram"},
	{prefix: "n2-", cpuSKU: "n2 instance core", ramSKU: "n2 instance ram"},
	{prefix: "n1-", cpuSKU: "n1 predefined instance core", ramSKU: "n1 predefined instance ram"},
	{prefix: "t2d-", cpuSKU: "t2d amd instance core", ramSKU: "t2d amd instance ram"},
	{prefix: "t2a-", cpuSKU: "t2a arm instance core", ramSKU: "t2a arm instance ram", arch: "arm64"},

	// Compute optimized
	{prefix: "c3-", cpuSKU: "c3 instance core", ramSKU: "c3 instance ram"},
	{prefix: "c2d-", cpuSKU: "c2d amd compute optimized core", ramSKU: "c2d amd compute optimized ram"},
	{prefix: "c2-", cpuSKU: "compute optimized core", ramSKU: "compute optimized ram"},

	// Memory optimized
	{prefix: "m3-", cpuSKU: "m3 memory-optimized instance core", ramSKU: "m3 memory-optimized instance ram"},
	{prefix: "m2-", cpuSKU: "m2 memory-optimized instance core", ramSKU: "m2 memory-optimized instance ram"},
	{prefix: "m1-", cpuSKU: "memory-optimized instance core", ramSKU: "memory-optimized instance ram"},

	// Accelerator-optimized — these have a GPU SKU on top of CPU/RAM.
	{prefix: "a3-", cpuSKU: "a3 instance core", ramSKU: "a3 instance ram",
		gpuSKU: "nvidia h100", gpuModel: "h100"},
	{prefix: "a2-", cpuSKU: "a2 instance core", ramSKU: "a2 instance ram",
		gpuSKU: "nvidia tesla a100", gpuModel: "a100"},
	{prefix: "g2-", cpuSKU: "g2 instance core", ramSKU: "g2 instance ram",
		gpuSKU: "nvidia l4", gpuModel: "l4"},
}

func matchGCPFamily(name string) *gcpFamily {
	for i := range gcpFamilies {
		if strings.HasPrefix(name, gcpFamilies[i].prefix) {
			return &gcpFamilies[i]
		}
	}
	return nil
}

// gcpFamilyPrices is the materialized per-family CPU/RAM/GPU rate.
type gcpFamilyPrices struct{ cpu, ram, gpu float64 }

// findGCPFamilyPrices builds a per-family pricing table by scanning the SKU
// list once. SKUs that aren't on-demand or aren't available in the region are
// skipped. When multiple SKUs match a description (e.g. different machine-type
// tiers within a family), the cheapest is used so the resulting per-core/RAM
// rate is conservative.
func findGCPFamilyPrices(skus []gcpSKU, region, usageType string) map[string]gcpFamilyPrices {
	out := make(map[string]gcpFamilyPrices, len(gcpFamilies))
	for i := range gcpFamilies {
		out[gcpFamilies[i].prefix] = gcpFamilyPrices{}
	}

	for _, s := range skus {
		if s.Category.ResourceFamily != "Compute" || s.Category.UsageType != usageType {
			continue
		}
		if !skuServesRegion(s.ServiceRegions, region) {
			continue
		}
		desc := strings.ToLower(s.Description)
		price := s.hourlyUSD()
		if price <= 0 {
			continue
		}
		for i := range gcpFamilies {
			fam := &gcpFamilies[i]
			fp := out[fam.prefix]
			switch {
			case strings.Contains(desc, fam.cpuSKU):
				if fp.cpu == 0 || price < fp.cpu {
					fp.cpu = price
				}
			case strings.Contains(desc, fam.ramSKU):
				if fp.ram == 0 || price < fp.ram {
					fp.ram = price
				}
			case fam.gpuSKU != "" && strings.Contains(desc, fam.gpuSKU):
				if fp.gpu == 0 || price < fp.gpu {
					fp.gpu = price
				}
			default:
				continue
			}
			out[fam.prefix] = fp
		}
	}
	return out
}

// gcpGPUCount derives GPU count from the machine-type name for accelerator
// families. Returns 0 for non-accelerator families or unrecognized names.
//
// A2/A3 names encode count as a "-Ng" suffix (e.g. a2-highgpu-4g → 4).
// G2 names use vCPU count; the GPU-to-vCPU mapping is irregular so we hard-
// code the known steps. Unknown sizes fall back to 1.
func gcpGPUCount(name string) int {
	switch {
	case strings.HasPrefix(name, "a2-"), strings.HasPrefix(name, "a3-"):
		// Trailing token like "1g", "4g", "16g".
		if idx := strings.LastIndex(name, "-"); idx >= 0 {
			tail := strings.TrimSuffix(name[idx+1:], "g")
			if n, err := strconv.Atoi(tail); err == nil {
				return n
			}
		}
	case strings.HasPrefix(name, "g2-standard-"):
		// g2-standard-{4,8,12,16,24,32,48,96} → {1,1,1,1,2,1,4,8}.
		// Match Google's published lookup; fall back to 1 for unrecognized sizes.
		cpus, err := strconv.Atoi(strings.TrimPrefix(name, "g2-standard-"))
		if err != nil {
			return 1
		}
		switch cpus {
		case 24:
			return 2
		case 48:
			return 4
		case 96:
			return 8
		default:
			return 1
		}
	}
	return 0
}

func joinGCPSpecsAndPrices(specs []gcpMachineType, skus []gcpSKU, region string) []InstanceType {
	prices := findGCPFamilyPrices(skus, region, "OnDemand")
	spotPrices := findGCPFamilyPrices(skus, region, "Preemptible")

	var out []InstanceType
	for _, s := range specs {
		fam := matchGCPFamily(s.Name)
		if fam == nil {
			continue
		}
		fp := prices[fam.prefix]
		if fp.cpu == 0 || fp.ram == 0 {
			continue // catalog didn't have pricing for this family in this region
		}
		// Accelerator families MUST also have GPU pricing or the estimate is wrong.
		if fam.gpuSKU != "" && fp.gpu == 0 {
			continue
		}

		memGB := float64(s.MemoryMb) / 1024.0
		gpuCount := gcpGPUCount(s.Name)
		price := fp.cpu*float64(s.GuestCpus) + fp.ram*memGB + fp.gpu*float64(gpuCount)
		if !isPlausibleHourlyPrice(price) {
			continue
		}

		arch := fam.arch
		if arch == "" {
			arch = "x86_64"
		}

		inst := InstanceType{
			Name:         s.Name,
			Provider:     ProviderGCP,
			VCPUs:        s.GuestCpus,
			MemoryGB:     memGB,
			PricePerHour: price,
			Arch:         arch,
			GPUCount:     gpuCount,
			GPUModel:     fam.gpuModel,
		}

		// Live preemptible (spot) price, when the catalog had Preemptible SKUs for
		// the whole family (CPU+RAM, plus GPU for accelerator families).
		if sp := spotPrices[fam.prefix]; sp.cpu > 0 && sp.ram > 0 && (fam.gpuSKU == "" || sp.gpu > 0) {
			spot := sp.cpu*float64(s.GuestCpus) + sp.ram*memGB + sp.gpu*float64(gpuCount)
			if isPlausibleHourlyPrice(spot) {
				inst.SpotPricePerHour = spot
			}
		}

		out = append(out, inst)
	}
	return out
}

func skuServesRegion(regions []string, want string) bool {
	for _, r := range regions {
		if r == want {
			return true
		}
	}
	return false
}

func isGcloudAuthErr(err error) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		s := string(ee.Stderr)
		return strings.Contains(s, "credentials") ||
			strings.Contains(s, "not currently logged in") ||
			strings.Contains(s, "Reauthentication") ||
			strings.Contains(s, "PERMISSION_DENIED") ||
			strings.Contains(s, "UNAUTHENTICATED")
	}
	return false
}
