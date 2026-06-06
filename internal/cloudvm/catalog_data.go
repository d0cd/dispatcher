package cloudvm

// defaultInstances contains curated instance types across all supported providers.
// Prices are approximate USD on-demand rates as of 2025.
var defaultInstances = []InstanceType{
	// --- Hetzner Cloud ---
	{Name: "cx22", Provider: ProviderHetzner, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.006, Arch: "x86_64"},
	{Name: "cx32", Provider: ProviderHetzner, VCPUs: 4, MemoryGB: 8, PricePerHour: 0.011, Arch: "x86_64"},
	{Name: "cx42", Provider: ProviderHetzner, VCPUs: 8, MemoryGB: 16, PricePerHour: 0.021, Arch: "x86_64"},
	{Name: "cx52", Provider: ProviderHetzner, VCPUs: 16, MemoryGB: 32, PricePerHour: 0.041, Arch: "x86_64"},
	{Name: "cpx21", Provider: ProviderHetzner, VCPUs: 3, MemoryGB: 4, PricePerHour: 0.008, Arch: "x86_64"},
	{Name: "cpx31", Provider: ProviderHetzner, VCPUs: 4, MemoryGB: 8, PricePerHour: 0.015, Arch: "x86_64"},
	{Name: "cpx41", Provider: ProviderHetzner, VCPUs: 8, MemoryGB: 16, PricePerHour: 0.029, Arch: "x86_64"},
	{Name: "cpx51", Provider: ProviderHetzner, VCPUs: 16, MemoryGB: 32, PricePerHour: 0.057, Arch: "x86_64"},
	{Name: "cax21", Provider: ProviderHetzner, VCPUs: 4, MemoryGB: 8, PricePerHour: 0.008, Arch: "arm64"},
	{Name: "cax31", Provider: ProviderHetzner, VCPUs: 8, MemoryGB: 16, PricePerHour: 0.015, Arch: "arm64"},
	{Name: "cax41", Provider: ProviderHetzner, VCPUs: 16, MemoryGB: 32, PricePerHour: 0.029, Arch: "arm64"},

	// --- AWS EC2 (us-east-1 on-demand) ---
	{Name: "t3.micro", Provider: ProviderAWS, VCPUs: 2, MemoryGB: 1, PricePerHour: 0.0104, Arch: "x86_64"},
	{Name: "t3.small", Provider: ProviderAWS, VCPUs: 2, MemoryGB: 2, PricePerHour: 0.0208, Arch: "x86_64"},
	{Name: "t3.medium", Provider: ProviderAWS, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.0416, Arch: "x86_64"},
	{Name: "t3.large", Provider: ProviderAWS, VCPUs: 2, MemoryGB: 8, PricePerHour: 0.0832, Arch: "x86_64"},
	{Name: "m5.large", Provider: ProviderAWS, VCPUs: 2, MemoryGB: 8, PricePerHour: 0.096, Arch: "x86_64"},
	{Name: "m5.xlarge", Provider: ProviderAWS, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.192, Arch: "x86_64"},
	{Name: "m5.2xlarge", Provider: ProviderAWS, VCPUs: 8, MemoryGB: 32, PricePerHour: 0.384, Arch: "x86_64"},
	{Name: "c5.large", Provider: ProviderAWS, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.085, Arch: "x86_64"},
	{Name: "c5.xlarge", Provider: ProviderAWS, VCPUs: 4, MemoryGB: 8, PricePerHour: 0.170, Arch: "x86_64"},
	{Name: "c5.2xlarge", Provider: ProviderAWS, VCPUs: 8, MemoryGB: 16, PricePerHour: 0.340, Arch: "x86_64"},
	{Name: "g4dn.xlarge", Provider: ProviderAWS, VCPUs: 4, MemoryGB: 16, GPUCount: 1, GPUModel: "t4", PricePerHour: 0.526, Arch: "x86_64"},
	{Name: "g4dn.2xlarge", Provider: ProviderAWS, VCPUs: 8, MemoryGB: 32, GPUCount: 1, GPUModel: "t4", PricePerHour: 0.752, Arch: "x86_64"},
	{Name: "p3.2xlarge", Provider: ProviderAWS, VCPUs: 8, MemoryGB: 61, GPUCount: 1, GPUModel: "v100", PricePerHour: 3.06, Arch: "x86_64"},
	{Name: "g5.xlarge", Provider: ProviderAWS, VCPUs: 4, MemoryGB: 16, GPUCount: 1, GPUModel: "a10g", PricePerHour: 1.006, Arch: "x86_64"},

	// --- GCP Compute Engine (us-central1) ---
	{Name: "e2-micro", Provider: ProviderGCP, VCPUs: 2, MemoryGB: 1, PricePerHour: 0.008, Arch: "x86_64"},
	{Name: "e2-small", Provider: ProviderGCP, VCPUs: 2, MemoryGB: 2, PricePerHour: 0.017, Arch: "x86_64"},
	{Name: "e2-medium", Provider: ProviderGCP, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.034, Arch: "x86_64"},
	{Name: "e2-standard-4", Provider: ProviderGCP, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.134, Arch: "x86_64"},
	{Name: "e2-standard-8", Provider: ProviderGCP, VCPUs: 8, MemoryGB: 32, PricePerHour: 0.268, Arch: "x86_64"},
	{Name: "n2-standard-2", Provider: ProviderGCP, VCPUs: 2, MemoryGB: 8, PricePerHour: 0.097, Arch: "x86_64"},
	{Name: "n2-standard-4", Provider: ProviderGCP, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.194, Arch: "x86_64"},
	{Name: "n2-standard-8", Provider: ProviderGCP, VCPUs: 8, MemoryGB: 32, PricePerHour: 0.388, Arch: "x86_64"},
	{Name: "c2-standard-4", Provider: ProviderGCP, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.210, Arch: "x86_64"},
	{Name: "t2a-standard-4", Provider: ProviderGCP, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.115, Arch: "arm64"},
	{Name: "g2-standard-4", Provider: ProviderGCP, VCPUs: 4, MemoryGB: 16, GPUCount: 1, GPUModel: "l4", PricePerHour: 0.700, Arch: "x86_64"},
	{Name: "a2-highgpu-1g", Provider: ProviderGCP, VCPUs: 12, MemoryGB: 85, GPUCount: 1, GPUModel: "a100", PricePerHour: 3.670, Arch: "x86_64"},

	// --- Azure VMs (East US) ---
	{Name: "Standard_B2s", Provider: ProviderAzure, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.042, Arch: "x86_64"},
	{Name: "Standard_B4ms", Provider: ProviderAzure, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.166, Arch: "x86_64"},
	{Name: "Standard_D2s_v5", Provider: ProviderAzure, VCPUs: 2, MemoryGB: 8, PricePerHour: 0.096, Arch: "x86_64"},
	{Name: "Standard_D4s_v5", Provider: ProviderAzure, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.192, Arch: "x86_64"},
	{Name: "Standard_D8s_v5", Provider: ProviderAzure, VCPUs: 8, MemoryGB: 32, PricePerHour: 0.384, Arch: "x86_64"},
	{Name: "Standard_F4s_v2", Provider: ProviderAzure, VCPUs: 4, MemoryGB: 8, PricePerHour: 0.170, Arch: "x86_64"},
	{Name: "Standard_F8s_v2", Provider: ProviderAzure, VCPUs: 8, MemoryGB: 16, PricePerHour: 0.340, Arch: "x86_64"},
	{Name: "Standard_NC4as_T4_v3", Provider: ProviderAzure, VCPUs: 4, MemoryGB: 28, GPUCount: 1, GPUModel: "t4", PricePerHour: 0.526, Arch: "x86_64"},
	{Name: "Standard_NC24ads_A100_v4", Provider: ProviderAzure, VCPUs: 24, MemoryGB: 220, GPUCount: 1, GPUModel: "a100", PricePerHour: 3.673, Arch: "x86_64"},

	// --- Hetzner GPU (dedicated) ---
	{Name: "gx11", Provider: ProviderHetzner, VCPUs: 8, MemoryGB: 32, GPUCount: 1, GPUModel: "a100", PricePerHour: 1.950, Arch: "x86_64"},
}
