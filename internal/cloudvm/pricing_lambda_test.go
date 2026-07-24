package cloudvm

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/d0cd/dispatcher/internal/secrets"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The real /instance-types envelope, trimmed to two types with differing
// regional capacity.
const lambdaInstanceTypesJSON = `{"data":{
  "gpu_1x_a10":{
    "instance_type":{"name":"gpu_1x_a10","gpu_description":"A10 (24 GB PCIe)","price_cents_per_hour":129,
      "specs":{"vcpus":30,"memory_gib":200,"storage_gib":1400,"gpus":1}},
    "regions_with_capacity_available":[{"name":"us-east-1"},{"name":"us-west-1"}]},
  "gpu_1x_a100_sxm4":{
    "instance_type":{"name":"gpu_1x_a100_sxm4","gpu_description":"A100 (40 GB SXM4)","price_cents_per_hour":199,
      "specs":{"vcpus":30,"memory_gib":200,"storage_gib":512,"gpus":1}},
    "regions_with_capacity_available":[{"name":"us-east-1"}]},
  "gpu_1x_h100_pcie":{
    "instance_type":{"name":"gpu_1x_h100_pcie","gpu_description":"H100 (80 GB PCIe)","price_cents_per_hour":249,
      "specs":{"vcpus":26,"memory_gib":200,"storage_gib":1024,"gpus":1}},
    "regions_with_capacity_available":[]}
}}`

func TestParseLambdaInstanceTypes_MapsPriceSpecsAndGPU(t *testing.T) {
	// Region empty: keep every type that has capacity somewhere (h100 has none).
	all, err := parseLambdaInstanceTypes([]byte(lambdaInstanceTypesJSON), "")
	require.NoError(t, err)
	require.Len(t, all, 2, "the no-capacity h100 is dropped")

	byName := map[string]InstanceType{}
	for _, it := range all {
		byName[it.Name] = it
	}
	a10 := byName["gpu_1x_a10"]
	assert.Equal(t, ProviderLambda, a10.Provider)
	assert.InDelta(t, 1.29, a10.PricePerHour, 0.001, "129 cents -> $1.29")
	assert.Equal(t, "a10", a10.GPUModel)
	assert.Equal(t, 1, a10.GPUCount)
	assert.Equal(t, 30, a10.VCPUs)
	assert.InDelta(t, 200, a10.MemoryGB, 0.001)
	assert.Equal(t, "x86_64", a10.Arch)
	assert.Equal(t, "a100", byName["gpu_1x_a100_sxm4"].GPUModel)
}

func TestParseLambdaInstanceTypes_RegionFilter(t *testing.T) {
	// us-west-1 only has capacity for the a10.
	west, err := parseLambdaInstanceTypes([]byte(lambdaInstanceTypesJSON), "us-west-1")
	require.NoError(t, err)
	require.Len(t, west, 1)
	assert.Equal(t, "gpu_1x_a10", west[0].Name)

	// A region with no capacity for any type yields nothing (not an error).
	none, err := parseLambdaInstanceTypes([]byte(lambdaInstanceTypesJSON), "asia-south-1")
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestLambdaFetcher_MissingKeySkips(t *testing.T) {
	f := &LambdaFetcher{apiKey: secret(""), baseURL: LambdaInstanceTypesURL}
	_, err := f.Fetch(context.Background())
	assert.True(t, errors.Is(err, ErrCredentialsMissing), "no key -> skip, never a hard error")
}

func TestLambdaGPUModel(t *testing.T) {
	assert.Equal(t, "a10", lambdaGPUModel("A10 (24 GB PCIe)"))
	assert.Equal(t, "a100", lambdaGPUModel("A100 (40 GB SXM4)"))
	assert.Equal(t, "gh200", lambdaGPUModel("GH200 (96 GB)"))
	assert.Equal(t, "", lambdaGPUModel(""))
}

// Pricing Lambda as a cross-provider alternative must never execute a configured
// secret command — that would shell out to the operator's (unlocked) secret
// manager on every plan/run, even for unrelated targets. The command runs only
// when the Lambda provider actually provisions. So the pricing fetcher reads the
// key from the environment only and self-skips when it isn't there.
func TestNewLambdaFetcher_DoesNotRunSecretCommand(t *testing.T) {
	os.Unsetenv("DISPATCHER_LAMBDA_API_KEY")
	secrets.SetGlobal(map[string][]string{
		"DISPATCHER_LAMBDA_API_KEY": {"printf", "secretval"},
	})
	t.Cleanup(func() {
		secrets.SetGlobal(nil)
		os.Unsetenv("DISPATCHER_LAMBDA_API_KEY")
	})
	f := NewLambdaFetcher("")
	f.baseURL = "http://127.0.0.1:1" // never reached once we skip on missing creds
	_, err := f.Fetch(context.Background())
	require.ErrorIs(t, err, ErrCredentialsMissing)
}
