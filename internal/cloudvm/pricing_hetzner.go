package cloudvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// HetznerFetcher pulls server types (with per-location pricing) from the
// hcloud CLI. It picks the cheapest location's price for each type so the
// catalog ranking stays comparable across providers.
type HetznerFetcher struct {
	// Location, when set, scopes pricing to a single location instead of
	// taking the cheapest one available.
	Location string
}

func NewHetznerFetcher() *HetznerFetcher { return &HetznerFetcher{} }

func (h *HetznerFetcher) Provider() ProviderID { return ProviderHetzner }

func (h *HetznerFetcher) Fetch(ctx context.Context) ([]InstanceType, error) {
	if _, err := exec.LookPath("hcloud"); err != nil {
		return nil, fmt.Errorf("%w: hcloud CLI not found", ErrCredentialsMissing)
	}

	out, err := exec.CommandContext(ctx, "hcloud", "server-type", "list", "-o", "json").Output()
	if err != nil {
		if isHcloudAuthErr(err) {
			return nil, ErrCredentialsMissing
		}
		return nil, fmt.Errorf("hcloud server-type list: %w", err)
	}

	return parseHetznerServerTypes(out, h.Location)
}

// hcloudServerType matches the subset of `hcloud server-type list -o json`
// output we care about.
type hcloudServerType struct {
	Name         string           `json:"name"`
	Cores        int              `json:"cores"`
	Memory       float64          `json:"memory"`
	Architecture string           `json:"architecture"`
	Deprecated   bool             `json:"deprecated"`
	Locations    []hcloudLocation `json:"locations"`
	Prices       []struct {
		Location    string `json:"location"`
		PriceHourly struct {
			Gross string `json:"gross"`
		} `json:"price_hourly"`
	} `json:"prices"`
}

func parseHetznerServerTypes(raw []byte, location string) ([]InstanceType, error) {
	var types []hcloudServerType
	if err := json.Unmarshal(raw, &types); err != nil {
		return nil, fmt.Errorf("parse hcloud output: %w", err)
	}

	var instances []InstanceType
	for _, t := range types {
		if t.Deprecated || !hetznerTypeAvailable(t.Locations, location) {
			continue
		}
		price, ok := cheapestHetznerPrice(t.Prices, t.Locations, location)
		if !ok || !isPlausibleHourlyPrice(price) {
			continue
		}
		instances = append(instances, InstanceType{
			Name:         t.Name,
			Provider:     ProviderHetzner,
			VCPUs:        t.Cores,
			MemoryGB:     t.Memory,
			PricePerHour: price,
			Arch:         normalizeHetznerArch(t.Architecture),
		})
	}
	return instances, nil
}

type hcloudLocation struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
}

func hetznerTypeAvailable(locations []hcloudLocation, scope string) bool {
	// Older hcloud versions and parser fixtures omit this field; in that case
	// retain the historical price-row behavior. Current hcloud output supplies
	// it, allowing us to avoid recommending retired/unavailable SKUs.
	if len(locations) == 0 {
		return true
	}
	for _, location := range locations {
		if location.Available && (scope == "" || location.Name == scope) {
			return true
		}
	}
	return false
}

func cheapestHetznerPrice(prices []struct {
	Location    string `json:"location"`
	PriceHourly struct {
		Gross string `json:"gross"`
	} `json:"price_hourly"`
}, locations []hcloudLocation, scope string) (float64, bool) {
	availabilityKnown := len(locations) > 0
	available := make(map[string]bool, len(locations))
	for _, location := range locations {
		available[location.Name] = location.Available
	}
	best := -1.0
	for _, p := range prices {
		if scope != "" && p.Location != scope {
			continue
		}
		if availabilityKnown && !available[p.Location] {
			continue
		}
		v, err := strconv.ParseFloat(p.PriceHourly.Gross, 64)
		if err != nil {
			continue
		}
		if best < 0 || v < best {
			best = v
		}
	}
	if best < 0 {
		return 0, false
	}
	return best, true
}

func normalizeHetznerArch(a string) string {
	switch strings.ToLower(a) {
	case "arm":
		return "arm64"
	case "x86":
		return "x86_64"
	}
	return a
}

func isHcloudAuthErr(err error) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		s := string(ee.Stderr)
		return strings.Contains(s, "no active context") || strings.Contains(s, "no token") || strings.Contains(s, "unauthorized")
	}
	return false
}
