package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// OCIPriceListURL is Oracle's public Cost Estimator price list (no auth). OCI
// prices Flex shapes per-OCPU-hour + per-GB-memory-hour, so a shape's hourly
// price is ocpus*ocpuRate + memGB*memRate.
const OCIPriceListURL = "https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?currencyCode=USD"

// ociPricedShape is a Flex shape dispatcher offers, with the standard pricing
// family that sets its per-OCPU/per-GB rates. OCPUs match ociFlexSizing (the
// VCPUs catalog field is treated as OCPUs on the OCI provisioning path).
type ociPricedShape struct {
	name   string
	family string // A1 / E4 / E5
	ocpus  int
	memGB  float64
	arch   string
}

var ociPricedShapes = []ociPricedShape{
	{"VM.Standard.A1.Flex", "A1", 2, 12, "arm64"},
	{"VM.Standard.E4.Flex", "E4", 2, 16, "x86_64"},
	{"VM.Standard.E5.Flex", "E5", 4, 32, "x86_64"},
}

// OCIFetcher prices OCI Flex shapes off the public price list. Unlike the other
// cloud fetchers it needs no credentials — the price list is public.
type OCIFetcher struct {
	client  *http.Client
	baseURL string
}

func NewOCIFetcher() *OCIFetcher {
	return &OCIFetcher{client: http.DefaultClient, baseURL: OCIPriceListURL}
}

func (o *OCIFetcher) Provider() ProviderID { return ProviderOCI }

func (o *OCIFetcher) Fetch(ctx context.Context) ([]InstanceType, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oci price list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oci price list: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	return parseOCIPrices(raw)
}

func parseOCIPrices(raw []byte) ([]InstanceType, error) {
	var body struct {
		Items []struct {
			DisplayName string `json:"displayName"`
			MetricName  string `json:"metricName"`
			Currency    []struct {
				Prices []struct {
					Model string  `json:"model"`
					Value float64 `json:"value"`
				} `json:"prices"`
			} `json:"currencyCodeLocalizations"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("parse oci price list: %w", err)
	}

	type rate struct{ ocpu, mem float64 }
	rates := map[string]*rate{}
	for _, it := range body.Items {
		fam := ociStandardFamily(strings.Join(strings.Fields(it.DisplayName), " "))
		if fam == "" {
			continue
		}
		price := 0.0
		for _, c := range it.Currency {
			for _, p := range c.Prices {
				if p.Model == "PAY_AS_YOU_GO" {
					price = p.Value
				}
			}
		}
		if price <= 0 {
			continue
		}
		r := rates[fam]
		if r == nil {
			r = &rate{}
			rates[fam] = r
		}
		switch {
		case strings.Contains(it.MetricName, "OCPU"):
			r.ocpu = price
		case strings.Contains(it.MetricName, "igabyte"): // "Gigabyte(s) Per Hour"
			r.mem = price
		}
	}

	var out []InstanceType
	for _, s := range ociPricedShapes {
		r := rates[s.family]
		if r == nil || r.ocpu <= 0 {
			continue
		}
		price := float64(s.ocpus)*r.ocpu + s.memGB*r.mem
		if !isPlausibleHourlyPrice(price) {
			continue
		}
		out = append(out, InstanceType{
			Name: s.name, Provider: ProviderOCI, VCPUs: s.ocpus,
			MemoryGB: s.memGB, PricePerHour: price, Arch: s.arch,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("oci price list: no standard flex compute rates found")
	}
	return out, nil
}

// ociStandardFamily returns the pricing family (A1/E4/E5) for a plain
// "Compute - Standard - <FAM>" OCPU/Memory product, or "" for anything else
// (Dense I/O, HPC, VMware, Ampere-flex "Ax", GPU, non-standard).
func ociStandardFamily(dn string) string {
	if !strings.Contains(dn, "Compute - Standard - ") {
		return ""
	}
	for _, bad := range []string{"Dense", "HPC", "VMware", "Customer", "Enterprise", " Ax"} {
		if strings.Contains(dn, bad) {
			return ""
		}
	}
	for _, fam := range []string{"A1", "E4", "E5"} {
		if strings.Contains(dn, "Standard - "+fam+" ") || strings.Contains(dn, "Standard - "+fam+"-") {
			return fam
		}
	}
	return ""
}
