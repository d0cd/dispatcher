package cloudvm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Hetzner: parser-level tests (no CLI dependency) -------------------------

func TestHetznerFetcher_Parse(t *testing.T) {
	// Two server types: cx22 (active) and cx11 (deprecated → skipped).
	raw := []byte(`[
		{
			"name": "cx22", "cores": 2, "memory": 4.0, "architecture": "x86", "deprecated": false,
			"prices": [
				{"location": "fsn1", "price_hourly": {"gross": "0.0070000000"}},
				{"location": "nbg1", "price_hourly": {"gross": "0.0060000000"}}
			]
		},
		{
			"name": "cx11", "cores": 1, "memory": 2.0, "architecture": "x86", "deprecated": true,
			"prices": [{"location": "fsn1", "price_hourly": {"gross": "0.0040000000"}}]
		},
		{
			"name": "cax21", "cores": 4, "memory": 8.0, "architecture": "arm", "deprecated": false,
			"prices": [{"location": "fsn1", "price_hourly": {"gross": "0.0080000000"}}]
		}
	]`)

	instances, err := parseHetznerServerTypes(raw, "")
	require.NoError(t, err)
	require.Len(t, instances, 2, "deprecated server types should be excluded")

	cx22 := instances[0]
	assert.Equal(t, "cx22", cx22.Name)
	assert.Equal(t, ProviderHetzner, cx22.Provider)
	assert.Equal(t, 2, cx22.VCPUs)
	assert.Equal(t, 4.0, cx22.MemoryGB)
	assert.Equal(t, "x86_64", cx22.Arch)
	assert.InDelta(t, 0.006, cx22.PricePerHour, 1e-6, "should pick cheapest location")

	cax21 := instances[1]
	assert.Equal(t, "arm64", cax21.Arch, "Hetzner 'arm' should normalize to arm64")
}

func TestHetznerFetcher_ParseWithLocationFilter(t *testing.T) {
	raw := []byte(`[
		{
			"name": "cx22", "cores": 2, "memory": 4.0, "architecture": "x86", "deprecated": false,
			"prices": [
				{"location": "fsn1", "price_hourly": {"gross": "0.0070000000"}},
				{"location": "nbg1", "price_hourly": {"gross": "0.0060000000"}}
			]
		}
	]`)

	instances, err := parseHetznerServerTypes(raw, "fsn1")
	require.NoError(t, err)
	require.Len(t, instances, 1)
	assert.InDelta(t, 0.007, instances[0].PricePerHour, 1e-6, "location filter should pin to fsn1")
}

func TestHetznerFetcher_LocationFilterExcludesUnavailableTypes(t *testing.T) {
	raw := []byte(`[
		{
			"name": "cx53", "cores": 16, "memory": 32.0, "architecture": "x86", "deprecated": false,
			"prices": [{"location": "hel1", "price_hourly": {"gross": "0.0561000000"}}],
			"locations": [{"name": "hel1", "available": false, "recommended": false}]
		},
		{
			"name": "cpx62", "cores": 16, "memory": 32.0, "architecture": "x86", "deprecated": false,
			"prices": [{"location": "hel1", "price_hourly": {"gross": "0.2452000000"}}],
			"locations": [{"name": "hel1", "available": true, "recommended": true}]
		}
	]`)

	instances, err := parseHetznerServerTypes(raw, "hel1")
	require.NoError(t, err)
	require.Len(t, instances, 1)
	assert.Equal(t, "cpx62", instances[0].Name,
		"a price row is not proof that a retired type can still be provisioned")
}

func TestHetznerFetcher_ParseEmpty(t *testing.T) {
	instances, err := parseHetznerServerTypes([]byte(`[]`), "")
	require.NoError(t, err)
	assert.Empty(t, instances)
}

// --- Azure: HTTP-level test with a test server ------------------------------

func TestAzureFetcher_Fetch(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`{
				"Items": [{
					"armSkuName": "Standard_F4s_v2", "retailPrice": 0.169,
					"productName": "Virtual Machines Fsv2 Series", "meterName": "F4s v2",
					"unitOfMeasure": "1 Hour", "type": "Consumption"
				}],
				"NextPageLink": ""
			}`))
			return
		}
		// Page 1: one valid instance, plus one Low-Priority and one Windows row
		// that should be filtered out, plus a NextPageLink pointing at page 2.
		body := `{
			"Items": [
				{
					"armSkuName": "Standard_D2s_v3", "retailPrice": 0.096,
					"productName": "Virtual Machines DSv3 Series", "meterName": "D2s v3",
					"unitOfMeasure": "1 Hour", "type": "Consumption"
				},
				{
					"armSkuName": "Standard_D2s_v3", "retailPrice": 0.012,
					"productName": "Virtual Machines DSv3 Series Low Priority",
					"meterName": "D2s v3 Low Priority",
					"unitOfMeasure": "1 Hour", "type": "Consumption"
				},
				{
					"armSkuName": "Standard_D2s_v3_Windows", "retailPrice": 0.188,
					"productName": "Virtual Machines DSv3 Series Windows", "meterName": "D2s v3",
					"unitOfMeasure": "1 Hour", "type": "Consumption"
				}
			],
			"NextPageLink": "` + srv.URL + `?page=2"
		}`
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	f := &AzureFetcher{Region: "eastus", BaseURL: srv.URL, Client: srv.Client()}
	instances, err := f.Fetch(context.Background())
	require.NoError(t, err)

	require.Len(t, instances, 2, "Low-Priority and Windows entries should be filtered out")
	assert.Equal(t, "Standard_D2s_v3", instances[0].Name)
	assert.Equal(t, ProviderAzure, instances[0].Provider)
	assert.Equal(t, 0.096, instances[0].PricePerHour)
	assert.Equal(t, "Standard_F4s_v2", instances[1].Name)
}

// --- AWS: parser-level tests ------------------------------------------------

func TestAWSFetcher_ParseBulkPriceList(t *testing.T) {
	// Realistic-shape Bulk Price List doc: products keyed by SKU, terms.OnDemand
	// keyed by the same SKU pointing at offers → priceDimensions → USD/Hrs.
	doc := `{
		"formatVersion": "v1.0",
		"products": {
			"SKU_T3MICRO": {
				"sku": "SKU_T3MICRO",
				"productFamily": "Compute Instance",
				"attributes": {
					"instanceType": "t3.micro",
					"vcpu": "2",
					"memory": "1 GiB",
					"operatingSystem": "Linux",
					"tenancy": "Shared",
					"preInstalledSw": "NA",
					"capacityStatus": "Used",
					"physicalProcessor": "Intel Skylake"
				}
			},
			"SKU_T4GSMALL": {
				"sku": "SKU_T4GSMALL",
				"productFamily": "Compute Instance",
				"attributes": {
					"instanceType": "t4g.small",
					"vcpu": "2",
					"memory": "2 GiB",
					"operatingSystem": "Linux",
					"tenancy": "Shared",
					"preInstalledSw": "NA",
					"capacityStatus": "Used",
					"physicalProcessor": "AWS Graviton2 Processor"
				}
			},
			"SKU_G4DN": {
				"sku": "SKU_G4DN",
				"productFamily": "Compute Instance",
				"attributes": {
					"instanceType": "g4dn.xlarge",
					"vcpu": "4",
					"memory": "16 GiB",
					"operatingSystem": "Linux",
					"tenancy": "Shared",
					"preInstalledSw": "NA",
					"capacityStatus": "Used",
					"gpu": "1",
					"physicalProcessor": "Intel Xeon"
				}
			},
			"SKU_WINDOWS": {
				"sku": "SKU_WINDOWS",
				"productFamily": "Compute Instance",
				"attributes": {
					"instanceType": "m5.large",
					"operatingSystem": "Windows",
					"tenancy": "Shared",
					"preInstalledSw": "NA",
					"capacityStatus": "Used"
				}
			},
			"SKU_STORAGE": {
				"sku": "SKU_STORAGE",
				"productFamily": "Storage",
				"attributes": {"volumeType": "gp3"}
			}
		},
		"terms": {
			"OnDemand": {
				"SKU_T3MICRO": {
					"SKU_T3MICRO.JRTCKXETXF": {
						"priceDimensions": {
							"SKU_T3MICRO.JRTCKXETXF.6YS6EN2CT7": {
								"unit": "Hrs",
								"pricePerUnit": {"USD": "0.0104"}
							}
						}
					}
				},
				"SKU_T4GSMALL": {
					"SKU_T4GSMALL.JRTCKXETXF": {
						"priceDimensions": {
							"SKU_T4GSMALL.JRTCKXETXF.6YS6EN2CT7": {
								"unit": "Hrs",
								"pricePerUnit": {"USD": "0.0168"}
							}
						}
					}
				},
				"SKU_G4DN": {
					"SKU_G4DN.JRTCKXETXF": {
						"priceDimensions": {
							"SKU_G4DN.JRTCKXETXF.6YS6EN2CT7": {
								"unit": "Hrs",
								"pricePerUnit": {"USD": "0.526"}
							}
						}
					}
				}
			}
		}
	}`

	instances, err := parseAWSBulkPriceList(strings.NewReader(doc))
	require.NoError(t, err)
	// Expect 3: Windows + Storage should be filtered out.
	require.Len(t, instances, 3, "Windows and Storage SKUs should be filtered out")

	byName := map[string]InstanceType{}
	for _, inst := range instances {
		byName[inst.Name] = inst
	}

	t3 := byName["t3.micro"]
	assert.Equal(t, ProviderAWS, t3.Provider)
	assert.Equal(t, 2, t3.VCPUs)
	assert.Equal(t, 1.0, t3.MemoryGB)
	assert.Equal(t, 0.0104, t3.PricePerHour)
	assert.Equal(t, "x86_64", t3.Arch)

	t4g := byName["t4g.small"]
	assert.Equal(t, "arm64", t4g.Arch, "Graviton physicalProcessor should normalize to arm64")

	g4dn := byName["g4dn.xlarge"]
	assert.Equal(t, 1, g4dn.GPUCount)
	assert.Equal(t, "t4", g4dn.GPUModel)
}

func TestIsPlausibleHourlyPrice(t *testing.T) {
	// Defense against poisoned bulk-JSON injecting absurd prices.
	cases := []struct {
		price float64
		want  bool
	}{
		{0.0042, true},  // cheapest real EC2 (t4g.nano)
		{0.5, true},     // typical mid-range
		{32.77, true},   // p4d.24xlarge — among the priciest standard on-demand
		{0.0, false},    // zero would tempt the planner into spam-launching
		{-1.0, false},   // negative
		{0.0001, false}, // suspiciously sub-cent
		{500.0, false},  // 5x the most expensive real SKU
		{200.0, true},   // right at the upper bound
	}
	for _, c := range cases {
		got := isPlausibleHourlyPrice(c.price)
		assert.Equal(t, c.want, got, "price=%f", c.price)
	}
}

func TestAWSFetcher_Fetch_HitsRegionURL(t *testing.T) {
	// httptest server stands in for the AWS bulk endpoint. Verifies the
	// fetcher constructs the right per-region URL.
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"products":{},"terms":{"OnDemand":{}}}`)
	}))
	defer srv.Close()

	f := &AWSFetcher{Region: "us-west-2", BaseURL: srv.URL, Client: srv.Client()}
	_, err := f.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "/us-west-2/index.json", gotPath)
}

// --- GCP: join logic with stub specs + SKUs ---------------------------------

func TestGCPFetcher_JoinSpecsAndPrices(t *testing.T) {
	specs := []gcpMachineType{
		{Name: "n1-standard-2", GuestCpus: 2, MemoryMb: 7680},
		{Name: "n1-standard-4", GuestCpus: 4, MemoryMb: 15360},
		// Unsupported family — should be filtered out.
		{Name: "a2-highgpu-1g", GuestCpus: 12, MemoryMb: 85000},
	}
	skus := []gcpSKU{
		{
			Description:    "N1 Predefined Instance Core running in Americas",
			ServiceRegions: []string{"us-central1"},
			Category: struct {
				ResourceFamily string `json:"resourceFamily"`
				ResourceGroup  string `json:"resourceGroup"`
				UsageType      string `json:"usageType"`
			}{ResourceFamily: "Compute", UsageType: "OnDemand"},
			PricingInfo: []struct {
				PricingExpression struct {
					TieredRates []struct {
						UnitPrice struct {
							Units string `json:"units"`
							Nanos int64  `json:"nanos"`
						} `json:"unitPrice"`
					} `json:"tieredRates"`
				} `json:"pricingExpression"`
			}{
				{PricingExpression: struct {
					TieredRates []struct {
						UnitPrice struct {
							Units string `json:"units"`
							Nanos int64  `json:"nanos"`
						} `json:"unitPrice"`
					} `json:"tieredRates"`
				}{TieredRates: []struct {
					UnitPrice struct {
						Units string `json:"units"`
						Nanos int64  `json:"nanos"`
					} `json:"unitPrice"`
				}{{UnitPrice: struct {
					Units string `json:"units"`
					Nanos int64  `json:"nanos"`
				}{Units: "0", Nanos: 31611000}}}}},
			},
		},
		{
			Description:    "N1 Predefined Instance Ram running in Americas",
			ServiceRegions: []string{"us-central1"},
			Category: struct {
				ResourceFamily string `json:"resourceFamily"`
				ResourceGroup  string `json:"resourceGroup"`
				UsageType      string `json:"usageType"`
			}{ResourceFamily: "Compute", UsageType: "OnDemand"},
			PricingInfo: []struct {
				PricingExpression struct {
					TieredRates []struct {
						UnitPrice struct {
							Units string `json:"units"`
							Nanos int64  `json:"nanos"`
						} `json:"unitPrice"`
					} `json:"tieredRates"`
				} `json:"pricingExpression"`
			}{
				{PricingExpression: struct {
					TieredRates []struct {
						UnitPrice struct {
							Units string `json:"units"`
							Nanos int64  `json:"nanos"`
						} `json:"unitPrice"`
					} `json:"tieredRates"`
				}{TieredRates: []struct {
					UnitPrice struct {
						Units string `json:"units"`
						Nanos int64  `json:"nanos"`
					} `json:"unitPrice"`
				}{{UnitPrice: struct {
					Units string `json:"units"`
					Nanos int64  `json:"nanos"`
				}{Units: "0", Nanos: 4237000}}}}},
			},
		},
	}

	instances := joinGCPSpecsAndPrices(specs, skus, "us-central1")
	require.Len(t, instances, 2, "a2-highgpu-1g is unsupported and should be filtered out")

	n1Std2 := instances[0]
	assert.Equal(t, "n1-standard-2", n1Std2.Name)
	assert.Equal(t, ProviderGCP, n1Std2.Provider)
	assert.Equal(t, 2, n1Std2.VCPUs)
	// 7680 MB / 1024 = 7.5 GB
	assert.InDelta(t, 7.5, n1Std2.MemoryGB, 1e-6)
	// 2 cores × $0.031611 + 7.5 GB × $0.004237 = $0.0949995
	assert.InDelta(t, 0.0949995, n1Std2.PricePerHour, 1e-6)
}

func TestGCPFetcher_JoinReturnsNilWithoutCorePrices(t *testing.T) {
	// No SKUs that match the N1 prefix → no core/ram price → empty result.
	specs := []gcpMachineType{{Name: "n1-standard-2", GuestCpus: 2, MemoryMb: 7680}}
	instances := joinGCPSpecsAndPrices(specs, nil, "us-central1")
	assert.Empty(t, instances)
}

// gcpComputeSKU is a test helper that builds a minimally-valid gcpSKU for the
// "Compute / OnDemand" path. nanos is the price-per-hour in 1e-9 USD units.
func gcpComputeSKU(description, region string, nanos int64) gcpSKU {
	var s gcpSKU
	s.Description = description
	s.ServiceRegions = []string{region}
	s.Category.ResourceFamily = "Compute"
	s.Category.UsageType = "OnDemand"
	s.PricingInfo = make([]struct {
		PricingExpression struct {
			TieredRates []struct {
				UnitPrice struct {
					Units string `json:"units"`
					Nanos int64  `json:"nanos"`
				} `json:"unitPrice"`
			} `json:"tieredRates"`
		} `json:"pricingExpression"`
	}, 1)
	rate := struct {
		UnitPrice struct {
			Units string `json:"units"`
			Nanos int64  `json:"nanos"`
		} `json:"unitPrice"`
	}{}
	rate.UnitPrice.Units = "0"
	rate.UnitPrice.Nanos = nanos
	s.PricingInfo[0].PricingExpression.TieredRates = []struct {
		UnitPrice struct {
			Units string `json:"units"`
			Nanos int64  `json:"nanos"`
		} `json:"unitPrice"`
	}{rate}
	return s
}

// E2 instances should price from "E2 Instance Core/Ram" SKUs, NOT the N1
// SKUs — verifies the per-family lookup table actually routes correctly.
func TestGCPFetcher_JoinE2Family(t *testing.T) {
	specs := []gcpMachineType{
		{Name: "e2-standard-4", GuestCpus: 4, MemoryMb: 16384},
	}
	skus := []gcpSKU{
		// Wrong family — should NOT be used for e2.
		gcpComputeSKU("N1 Predefined Instance Core running in Americas", "us-central1", 999_000_000),
		gcpComputeSKU("N1 Predefined Instance Ram running in Americas", "us-central1", 999_000_000),
		// Right family.
		gcpComputeSKU("E2 Instance Core running in Americas", "us-central1", 22_181_000),
		gcpComputeSKU("E2 Instance Ram running in Americas", "us-central1", 2_974_000),
	}

	instances := joinGCPSpecsAndPrices(specs, skus, "us-central1")
	require.Len(t, instances, 1)
	e2 := instances[0]
	assert.Equal(t, "e2-standard-4", e2.Name)
	assert.Equal(t, 4, e2.VCPUs)
	assert.Equal(t, 16.0, e2.MemoryGB)
	// 4 × 0.022181 + 16 × 0.002974 = 0.088724 + 0.047584 = 0.136308
	assert.InDelta(t, 0.136308, e2.PricePerHour, 1e-5)
	assert.Equal(t, 0, e2.GPUCount)
	assert.Empty(t, e2.GPUModel)
}

// A2 (NVIDIA A100) — verifies GPU-bearing families pull the right GPU SKU and
// the GPU count is derived from the machine-type suffix.
func TestGCPFetcher_JoinA2Family_WithGPU(t *testing.T) {
	specs := []gcpMachineType{
		{Name: "a2-highgpu-1g", GuestCpus: 12, MemoryMb: 85_000},
		{Name: "a2-highgpu-4g", GuestCpus: 48, MemoryMb: 340_000},
	}
	skus := []gcpSKU{
		gcpComputeSKU("A2 Instance Core running in Americas", "us-central1", 31_611_000),
		gcpComputeSKU("A2 Instance Ram running in Americas", "us-central1", 4_237_000),
		gcpComputeSKU("Nvidia Tesla A100 GPU running in Americas", "us-central1", 2_933_908_000),
	}

	instances := joinGCPSpecsAndPrices(specs, skus, "us-central1")
	require.Len(t, instances, 2)

	byName := map[string]InstanceType{}
	for _, i := range instances {
		byName[i.Name] = i
	}

	one := byName["a2-highgpu-1g"]
	assert.Equal(t, 1, one.GPUCount, "trailing -1g should yield 1 GPU")
	assert.Equal(t, "a100", one.GPUModel)
	// 12 × 0.031611 + (85000/1024) × 0.004237 + 1 × 2.933908 = ~3.66
	assert.Greater(t, one.PricePerHour, 3.0)

	four := byName["a2-highgpu-4g"]
	assert.Equal(t, 4, four.GPUCount, "trailing -4g should yield 4 GPUs")
}

// G2 (NVIDIA L4) — GPU count comes from a vCPU-to-GPU lookup, not the suffix.
func TestGCPFetcher_JoinG2Family_GPUCountByVCPU(t *testing.T) {
	specs := []gcpMachineType{
		{Name: "g2-standard-4", GuestCpus: 4, MemoryMb: 16_384},    // 1 GPU
		{Name: "g2-standard-48", GuestCpus: 48, MemoryMb: 192_000}, // 4 GPUs
		{Name: "g2-standard-96", GuestCpus: 96, MemoryMb: 384_000}, // 8 GPUs
	}
	skus := []gcpSKU{
		gcpComputeSKU("G2 Instance Core running in Americas", "us-central1", 22_000_000),
		gcpComputeSKU("G2 Instance Ram running in Americas", "us-central1", 2_500_000),
		gcpComputeSKU("Nvidia L4 GPU running in Americas", "us-central1", 700_000_000),
	}

	instances := joinGCPSpecsAndPrices(specs, skus, "us-central1")
	require.Len(t, instances, 3)

	byName := map[string]InstanceType{}
	for _, i := range instances {
		byName[i.Name] = i
	}
	assert.Equal(t, 1, byName["g2-standard-4"].GPUCount)
	assert.Equal(t, 4, byName["g2-standard-48"].GPUCount)
	assert.Equal(t, 8, byName["g2-standard-96"].GPUCount)
	assert.Equal(t, "l4", byName["g2-standard-4"].GPUModel)
}

// Accelerator families without GPU SKU pricing must be dropped — surfacing a
// GPU instance with a CPU-only price would mislead the planner.
func TestGCPFetcher_AcceleratorWithoutGPUSKUIsDropped(t *testing.T) {
	specs := []gcpMachineType{
		{Name: "a2-highgpu-1g", GuestCpus: 12, MemoryMb: 85_000},
	}
	// CPU + RAM SKUs present, GPU SKU MISSING.
	skus := []gcpSKU{
		gcpComputeSKU("A2 Instance Core running in Americas", "us-central1", 31_611_000),
		gcpComputeSKU("A2 Instance Ram running in Americas", "us-central1", 4_237_000),
	}
	instances := joinGCPSpecsAndPrices(specs, skus, "us-central1")
	assert.Empty(t, instances, "accelerator family without GPU pricing should be dropped, not under-priced")
}

// T2A (Arm) — verifies the arch override flows through.
func TestGCPFetcher_T2AFamilyIsArm64(t *testing.T) {
	specs := []gcpMachineType{
		{Name: "t2a-standard-4", GuestCpus: 4, MemoryMb: 16_384},
	}
	skus := []gcpSKU{
		gcpComputeSKU("T2A Arm Instance Core running in Americas", "us-central1", 15_000_000),
		gcpComputeSKU("T2A Arm Instance Ram running in Americas", "us-central1", 2_000_000),
	}
	instances := joinGCPSpecsAndPrices(specs, skus, "us-central1")
	require.Len(t, instances, 1)
	assert.Equal(t, "arm64", instances[0].Arch)
}

// Unknown / unsupported families must NOT leak into the catalog (the previous
// implementation silently included them with whatever CPU/RAM price it had).
func TestGCPFetcher_UnknownFamilyIsDropped(t *testing.T) {
	specs := []gcpMachineType{
		{Name: "z9-mystery-2", GuestCpus: 2, MemoryMb: 8_192},
	}
	skus := []gcpSKU{
		gcpComputeSKU("N1 Predefined Instance Core running in Americas", "us-central1", 31_611_000),
		gcpComputeSKU("N1 Predefined Instance Ram running in Americas", "us-central1", 4_237_000),
	}
	instances := joinGCPSpecsAndPrices(specs, skus, "us-central1")
	assert.Empty(t, instances)
}

func TestGCPFetcher_GPUCountDerivation(t *testing.T) {
	cases := []struct {
		name string
		want int
	}{
		{"a2-highgpu-1g", 1},
		{"a2-highgpu-4g", 4},
		{"a2-megagpu-16g", 16},
		{"a3-highgpu-8g", 8},
		{"g2-standard-4", 1},
		{"g2-standard-16", 1},
		{"g2-standard-24", 2},
		{"g2-standard-48", 4},
		{"g2-standard-96", 8},
		// CPU-only families: zero GPUs.
		{"n1-standard-4", 0},
		{"e2-standard-2", 0},
		{"c2-standard-30", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, gcpGPUCount(c.name))
		})
	}
}

func TestGCPFetcher_MatchFamily(t *testing.T) {
	cases := []struct {
		name       string
		wantPrefix string
	}{
		{"n1-standard-4", "n1-"},
		{"n2-highmem-8", "n2-"},
		{"n2d-standard-16", "n2d-"},
		{"e2-medium", "e2-"},
		{"c2-standard-30", "c2-"},
		{"c2d-highcpu-8", "c2d-"},
		{"c3-standard-22", "c3-"},
		{"m1-megamem-96", "m1-"},
		{"a2-highgpu-1g", "a2-"},
		{"a3-megagpu-8g", "a3-"},
		{"g2-standard-4", "g2-"},
		{"t2d-standard-4", "t2d-"},
		{"t2a-standard-4", "t2a-"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fam := matchGCPFamily(c.name)
			require.NotNil(t, fam, "expected family match for %s", c.name)
			assert.Equal(t, c.wantPrefix, fam.prefix)
		})
	}
}

// --- NewLiveCatalog: aggregation, skipping, error propagation ---------------

type fakeFetcher struct {
	provider  ProviderID
	instances []InstanceType
	err       error
}

func (f *fakeFetcher) Provider() ProviderID { return f.provider }
func (f *fakeFetcher) Fetch(context.Context) ([]InstanceType, error) {
	return f.instances, f.err
}

func TestNewLiveCatalog_Aggregates(t *testing.T) {
	cat, skipped, err := NewLiveCatalog(context.Background(),
		&fakeFetcher{provider: ProviderHetzner, instances: []InstanceType{
			{Name: "cx22", Provider: ProviderHetzner, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.006, Arch: "x86_64"},
		}},
		&fakeFetcher{provider: ProviderAzure, instances: []InstanceType{
			{Name: "Standard_D2s_v3", Provider: ProviderAzure, VCPUs: 2, MemoryGB: 8, PricePerHour: 0.096, Arch: "x86_64"},
		}},
	)
	require.NoError(t, err)
	assert.Empty(t, skipped)
	provs := providerSet(cat.instances)
	assert.True(t, provs[ProviderHetzner] && provs[ProviderAzure], "both providers' instances aggregated")
}

func providerSet(insts []InstanceType) map[ProviderID]bool {
	m := map[ProviderID]bool{}
	for _, i := range insts {
		m[i.Provider] = true
	}
	return m
}

func TestNewLiveCatalog_SkipsMissingCreds(t *testing.T) {
	cat, skipped, err := NewLiveCatalog(context.Background(),
		&fakeFetcher{provider: ProviderHetzner, instances: []InstanceType{
			{Name: "cx22", Provider: ProviderHetzner, PricePerHour: 0.006},
		}},
		&fakeFetcher{provider: ProviderAWS, err: ErrCredentialsMissing},
	)
	require.NoError(t, err)
	require.Len(t, skipped, 1)
	assert.Equal(t, ProviderAWS, skipped[0].Provider)
	assert.Contains(t, skipped[0].Reason, "credentials")
	assert.False(t, providerSet(cat.instances)[ProviderAWS], "skipped providers contribute no instances")
}

func TestNewLiveCatalog_EmptyFetchIsSkippedNotGPUSeeded(t *testing.T) {
	// A fetch that returns zero instances (e.g. the AWS bulk price list is too
	// large to parse within the timeout) must be treated as a skip. Otherwise
	// seedStaticGPU back-fills only the provider's static GPU instances, leaving
	// a GPU-only catalog that mis-recommends a GPU box for a plain workload.
	cat, skipped, err := NewLiveCatalog(context.Background(),
		&fakeFetcher{provider: ProviderAWS}, // 0 instances, no error
	)
	require.NoError(t, err)
	require.Len(t, skipped, 1)
	assert.Equal(t, ProviderAWS, skipped[0].Provider)
	assert.Empty(t, cat.FindCheapestForProvider(ProviderAWS, InstanceRequirements{GPUCount: 1}),
		"an empty fetch must not be back-filled with static GPU instances")
}

func TestNewLiveCatalog_SkipsOnTransientError(t *testing.T) {
	// Bias is toward "skip and continue" — a partial catalog is more useful
	// than no catalog, especially during pre-flight commands like `audit`.
	cat, skipped, err := NewLiveCatalog(context.Background(),
		&fakeFetcher{provider: ProviderHetzner, err: errors.New("network exploded")},
		&fakeFetcher{provider: ProviderAzure, instances: []InstanceType{
			{Name: "Standard_D2s_v3", Provider: ProviderAzure, PricePerHour: 0.096},
		}},
	)
	require.NoError(t, err)
	require.Len(t, skipped, 1)
	assert.Equal(t, ProviderHetzner, skipped[0].Provider)
	assert.Contains(t, skipped[0].Reason, "transient")
	assert.Contains(t, skipped[0].Reason, "network exploded")
	provs := providerSet(cat.instances)
	assert.True(t, provs[ProviderAzure], "the other provider's data should still load")
	assert.False(t, provs[ProviderHetzner], "the failed provider contributes nothing")
}

// A provider whose live feed returns no GPU rows (Azure today) must still
// resolve a GPU instance from the static catalog, so a GPU workload isn't
// refused at provisioning.
func TestNewLiveCatalog_SeedsStaticGPUWhenFeedHasNone(t *testing.T) {
	cat, _, err := NewLiveCatalog(context.Background(), &fakeFetcher{
		provider:  ProviderAzure,
		instances: []InstanceType{{Name: "Standard_B2s", Provider: ProviderAzure, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.042}},
	})
	require.NoError(t, err)

	gpu := cat.FindCheapestForProvider(ProviderAzure, InstanceRequirements{GPUCount: 1})
	require.NotEmpty(t, gpu, "GPU workload on Azure must resolve a static GPU instance when the live feed has none")
	assert.GreaterOrEqual(t, gpu[0].GPUCount, 1)
}

// Hetzner Cloud has no GPU SKU, so the catalog must never resolve a GPU instance
// for it — provisioning would otherwise send a phantom server type to hcloud.
func TestCatalog_HetznerHasNoGPU(t *testing.T) {
	assert.Empty(t, NewCatalog().FindCheapestForProvider(ProviderHetzner, InstanceRequirements{GPUCount: 1}),
		"Hetzner Cloud offers no GPU server type")
}

// A provider whose live feed already includes GPU rows must keep only those —
// no duplicate static rows.
func TestNewLiveCatalog_DoesNotSeedWhenFeedHasGPU(t *testing.T) {
	cat, _, err := NewLiveCatalog(context.Background(), &fakeFetcher{
		provider: ProviderAWS,
		instances: []InstanceType{
			{Name: "live-gpu", Provider: ProviderAWS, VCPUs: 4, MemoryGB: 16, GPUCount: 1, GPUModel: "t4", PricePerHour: 0.5},
		},
	})
	require.NoError(t, err)

	gpu := cat.FindCheapestForProvider(ProviderAWS, InstanceRequirements{GPUCount: 1})
	require.Len(t, gpu, 1, "should use only the live GPU row, not also static AWS GPU rows")
	assert.Equal(t, "live-gpu", gpu[0].Name)
}
