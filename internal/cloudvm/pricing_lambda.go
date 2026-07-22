package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// LambdaInstanceTypesURL is the Lambda Cloud endpoint that lists instance types
// with their per-hour price and current regional capacity. It requires the API
// key (unlike Azure/GCP retail pricing), so the fetcher self-skips when unset.
const LambdaInstanceTypesURL = "https://cloud.lambda.ai/api/v1/instance-types"

// LambdaFetcher pulls the GPU instance catalog + pricing from the Lambda Cloud
// API. Region, when set, filters to types with capacity there; empty keeps every
// type that has capacity somewhere (so plan can still price them). The API key is
// held as a redacting secret and only revealed into the Authorization header.
type LambdaFetcher struct {
	Region  string
	apiKey  secret
	client  *http.Client
	baseURL string // test override
}

func NewLambdaFetcher(region string) *LambdaFetcher {
	return &LambdaFetcher{
		Region:  region,
		apiKey:  secret(os.Getenv("DISPATCHER_LAMBDA_API_KEY")),
		client:  http.DefaultClient,
		baseURL: LambdaInstanceTypesURL,
	}
}

func (l *LambdaFetcher) Provider() ProviderID { return ProviderLambda }

func (l *LambdaFetcher) Fetch(ctx context.Context) ([]InstanceType, error) {
	if l.apiKey.empty() {
		return nil, ErrCredentialsMissing
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.baseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+l.apiKey.reveal())

	client := l.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	// A rejected key is "skip this provider", not a hard error that could bubble
	// the request up a log; the status carries no secret.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrCredentialsMissing
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("lambda instance-types: HTTP %d", resp.StatusCode)
	}
	return parseLambdaInstanceTypes(raw, l.Region)
}

// parseLambdaInstanceTypes maps the /instance-types response into catalog
// entries. A type with no current capacity (in the region, or anywhere when
// region is empty) is dropped so the planner never recommends an unlaunchable box.
func parseLambdaInstanceTypes(raw []byte, region string) ([]InstanceType, error) {
	var resp struct {
		Data map[string]struct {
			InstanceType struct {
				Name              string `json:"name"`
				GPUDescription    string `json:"gpu_description"`
				PriceCentsPerHour int    `json:"price_cents_per_hour"`
				Specs             struct {
					VCPUs     int `json:"vcpus"`
					MemoryGiB int `json:"memory_gib"`
					GPUs      int `json:"gpus"`
				} `json:"specs"`
			} `json:"instance_type"`
			Regions []struct {
				Name string `json:"name"`
			} `json:"regions_with_capacity_available"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse lambda instance-types: %w", err)
	}

	var out []InstanceType
	for _, v := range resp.Data {
		regions := make(map[string]bool, len(v.Regions))
		for _, r := range v.Regions {
			regions[r.Name] = true
		}
		if region != "" {
			if !regions[region] {
				continue
			}
		} else if len(regions) == 0 {
			continue
		}
		it := v.InstanceType
		out = append(out, InstanceType{
			Name:         it.Name,
			Provider:     ProviderLambda,
			VCPUs:        it.Specs.VCPUs,
			MemoryGB:     float64(it.Specs.MemoryGiB),
			GPUCount:     it.Specs.GPUs,
			GPUModel:     lambdaGPUModel(it.GPUDescription),
			PricePerHour: float64(it.PriceCentsPerHour) / 100.0,
			Arch:         "x86_64",
		})
	}
	return out, nil
}

// lambdaGPUModel reduces a gpu_description like "A10 (24 GB PCIe)" or
// "A100 (40 GB SXM4)" to the catalog model token ("a10", "a100").
func lambdaGPUModel(desc string) string {
	fields := strings.Fields(desc)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(fields[0])
}
