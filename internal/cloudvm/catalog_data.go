package cloudvm

// defaultInstances contains curated instance types across all supported providers.
// Prices are approximate USD on-demand rates as of 2025.
var defaultInstances = []InstanceType{
	// --- Hetzner Cloud ---
	{Name: "cx22", Provider: ProviderHetzner, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.006, Arch: "x86_64"},
	{Name: "cx32", Provider: ProviderHetzner, VCPUs: 4, MemoryGB: 8, PricePerHour: 0.011, Arch: "x86_64"},
	{Name: "cx42", Provider: ProviderHetzner, VCPUs: 8, MemoryGB: 16, PricePerHour: 0.021, Arch: "x86_64"},
	{Name: "cpx21", Provider: ProviderHetzner, VCPUs: 3, MemoryGB: 4, PricePerHour: 0.008, Arch: "x86_64"},
	{Name: "cpx31", Provider: ProviderHetzner, VCPUs: 4, MemoryGB: 8, PricePerHour: 0.015, Arch: "x86_64"},
	{Name: "cpx41", Provider: ProviderHetzner, VCPUs: 8, MemoryGB: 16, PricePerHour: 0.029, Arch: "x86_64"},
	{Name: "cpx62", Provider: ProviderHetzner, VCPUs: 16, MemoryGB: 32, PricePerHour: 0.2452, Arch: "x86_64"},
	{Name: "cax11", Provider: ProviderHetzner, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.006, Arch: "arm64"},
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
	// SEV-SNP CVM SKU the AWS confidential adapter forces when no instance type is
	// pinned (awsInstanceType); priced so a confidential run isn't costed as t3.micro.
	{Name: "m6a.large", Provider: ProviderAWS, VCPUs: 2, MemoryGB: 8, PricePerHour: 0.0864, Arch: "x86_64", Confidential: true},
	{Name: "g4dn.xlarge", Provider: ProviderAWS, VCPUs: 4, MemoryGB: 16, GPUCount: 1, GPUModel: "t4", PricePerHour: 0.526, Arch: "x86_64"},
	{Name: "g4dn.2xlarge", Provider: ProviderAWS, VCPUs: 8, MemoryGB: 32, GPUCount: 1, GPUModel: "t4", PricePerHour: 0.752, Arch: "x86_64"},
	{Name: "p3.2xlarge", Provider: ProviderAWS, VCPUs: 8, MemoryGB: 61, GPUCount: 1, GPUModel: "v100", PricePerHour: 3.06, Arch: "x86_64"},
	{Name: "g5.xlarge", Provider: ProviderAWS, VCPUs: 4, MemoryGB: 16, GPUCount: 1, GPUModel: "a10g", PricePerHour: 1.006, Arch: "x86_64"},
	// AWS offers a100 only in the 8-GPU p4d family (no single-a100 SKU); listed so an
	// a100 request on aws-vm resolves + prices offline instead of falling to the rate
	// card and mis-ranking as cheapest (the live fetcher maps p4d -> a100 too).
	{Name: "p4d.24xlarge", Provider: ProviderAWS, VCPUs: 96, MemoryGB: 1152, GPUCount: 8, GPUModel: "a100", PricePerHour: 32.7726, Arch: "x86_64"},

	// --- GCP Compute Engine (us-central1) ---
	{Name: "e2-micro", Provider: ProviderGCP, VCPUs: 2, MemoryGB: 1, PricePerHour: 0.008, Arch: "x86_64"},
	{Name: "e2-small", Provider: ProviderGCP, VCPUs: 2, MemoryGB: 2, PricePerHour: 0.017, Arch: "x86_64"},
	{Name: "e2-medium", Provider: ProviderGCP, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.034, Arch: "x86_64"},
	{Name: "e2-standard-4", Provider: ProviderGCP, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.134, Arch: "x86_64"},
	{Name: "e2-standard-8", Provider: ProviderGCP, VCPUs: 8, MemoryGB: 32, PricePerHour: 0.268, Arch: "x86_64"},
	{Name: "n2-standard-2", Provider: ProviderGCP, VCPUs: 2, MemoryGB: 8, PricePerHour: 0.097, Arch: "x86_64"},
	// AMD SEV-capable SKU the GCP confidential paths force when no machine type is
	// pinned (Confidential Space provisioning + gcp.go); base n2d plus the
	// Confidential VM premium, so a confidential run isn't costed as e2-micro.
	{Name: "n2d-standard-2", Provider: ProviderGCP, VCPUs: 2, MemoryGB: 8, PricePerHour: 0.085, Arch: "x86_64", Confidential: true},
	{Name: "n2-standard-4", Provider: ProviderGCP, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.194, Arch: "x86_64"},
	{Name: "n2-standard-8", Provider: ProviderGCP, VCPUs: 8, MemoryGB: 32, PricePerHour: 0.388, Arch: "x86_64"},
	{Name: "c2-standard-4", Provider: ProviderGCP, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.210, Arch: "x86_64"},
	{Name: "t2a-standard-4", Provider: ProviderGCP, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.115, Arch: "arm64"},
	{Name: "g2-standard-4", Provider: ProviderGCP, VCPUs: 4, MemoryGB: 16, GPUCount: 1, GPUModel: "l4", PricePerHour: 0.700, Arch: "x86_64"},
	{Name: "a2-highgpu-1g", Provider: ProviderGCP, VCPUs: 12, MemoryGB: 85, GPUCount: 1, GPUModel: "a100", PricePerHour: 3.670, Arch: "x86_64"},
	// GCP h100 (a3 family); listed so an h100 request on gcp-vm resolves + prices
	// offline instead of falling to the rate card (the live fetcher maps a3 -> h100).
	{Name: "a3-highgpu-1g", Provider: ProviderGCP, VCPUs: 26, MemoryGB: 234, GPUCount: 1, GPUModel: "h100", PricePerHour: 11.06, Arch: "x86_64"},

	// --- Azure VMs (East US) ---
	{Name: "Standard_B2s", Provider: ProviderAzure, VCPUs: 2, MemoryGB: 4, PricePerHour: 0.042, Arch: "x86_64"},
	{Name: "Standard_B4ms", Provider: ProviderAzure, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.166, Arch: "x86_64"},
	{Name: "Standard_D2s_v5", Provider: ProviderAzure, VCPUs: 2, MemoryGB: 8, PricePerHour: 0.096, Arch: "x86_64"},
	{Name: "Standard_D4s_v5", Provider: ProviderAzure, VCPUs: 4, MemoryGB: 16, PricePerHour: 0.192, Arch: "x86_64"},
	{Name: "Standard_D8s_v5", Provider: ProviderAzure, VCPUs: 8, MemoryGB: 32, PricePerHour: 0.384, Arch: "x86_64"},
	{Name: "Standard_F4s_v2", Provider: ProviderAzure, VCPUs: 4, MemoryGB: 8, PricePerHour: 0.170, Arch: "x86_64"},
	{Name: "Standard_F8s_v2", Provider: ProviderAzure, VCPUs: 8, MemoryGB: 16, PricePerHour: 0.340, Arch: "x86_64"},
	// SEV-SNP CVM SKU the Azure confidential adapter forces when no instance type is
	// pinned (azure.go); priced so a confidential run isn't costed as Standard_B2s.
	{Name: "Standard_DC2ads_v5", Provider: ProviderAzure, VCPUs: 2, MemoryGB: 8, PricePerHour: 0.096, Arch: "x86_64", Confidential: true},
	{Name: "Standard_NC4as_T4_v3", Provider: ProviderAzure, VCPUs: 4, MemoryGB: 28, GPUCount: 1, GPUModel: "t4", PricePerHour: 0.526, Arch: "x86_64"},
	{Name: "Standard_NC24ads_A100_v4", Provider: ProviderAzure, VCPUs: 24, MemoryGB: 220, GPUCount: 1, GPUModel: "a100", PricePerHour: 3.673, Arch: "x86_64"},

	// Hetzner Cloud offers no GPU server type (its GPUs are dedicated/Robot
	// servers, not provisionable via the Cloud API), so no Hetzner GPU row.

	// --- Oracle Cloud (OCI) ---
	// Provisioning only: OCI does not support dispatcher's confidential model
	// (see docs/SECURITY.md), so no shape advertises the Confidential capability.
	{Name: "VM.Standard.A1.Flex", Provider: ProviderOCI, VCPUs: 2, MemoryGB: 12, PricePerHour: 0.012, Arch: "arm64"},
	{Name: "VM.Standard.E4.Flex", Provider: ProviderOCI, VCPUs: 2, MemoryGB: 16, PricePerHour: 0.074, Arch: "x86_64"},
	{Name: "VM.Standard.E5.Flex", Provider: ProviderOCI, VCPUs: 4, MemoryGB: 32, PricePerHour: 0.148, Arch: "x86_64"},
}
