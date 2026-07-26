package cloudvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubCLI installs a PATH shim named `bin` that records its argv to argvFile and
// echoes `stdout` for every call, so a provider's CreateVM can be exercised and
// its argv asserted without a live cloud.
func stubCLI(t *testing.T, bin, stdout string) string {
	t.Helper()
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + argvFile + "\"\n" + stdout
	require.NoError(t, os.WriteFile(filepath.Join(dir, bin), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argvFile
}

func TestGCPCreateVM_SpotFlags(t *testing.T) {
	argv := stubCLI(t, "gcloud",
		"cat <<'JSON'\n[{\"name\":\"n\",\"networkInterfaces\":[{\"accessConfigs\":[{\"natIP\":\"1.2.3.4\"}]}]}]\nJSON\n")

	_, err := NewGCPProvider("proj", "us-central1-a").CreateVM(context.Background(),
		VMOptions{Name: "n", Spot: true, Tags: map[string]string{"dispatcher": "true"}})
	require.NoError(t, err)

	data, _ := os.ReadFile(argv)
	assert.Contains(t, string(data), "--provisioning-model=SPOT")
	assert.Contains(t, string(data), "--instance-termination-action=DELETE")
	assert.Contains(t, string(data), "--maintenance-policy=TERMINATE", "spot VMs can't live-migrate")
}

func TestGCPCreateVM_NoSpotFlagsWhenOnDemand(t *testing.T) {
	argv := stubCLI(t, "gcloud",
		"cat <<'JSON'\n[{\"name\":\"n\",\"networkInterfaces\":[{\"accessConfigs\":[{\"natIP\":\"1.2.3.4\"}]}]}]\nJSON\n")

	_, err := NewGCPProvider("proj", "us-central1-a").CreateVM(context.Background(),
		VMOptions{Name: "n", Tags: map[string]string{"dispatcher": "true"}})
	require.NoError(t, err)
	assert.NotContains(t, mustRead(t, argv), "--provisioning-model=SPOT", "on-demand must not request spot")
}

func TestAzureCreateVM_SpotFlags(t *testing.T) {
	argv := stubCLI(t, "az", "echo '{\"id\":\"/subscriptions/x/rg/vm/n\",\"publicIpAddress\":\"1.2.3.4\"}'\n")

	_, err := NewAzureProvider("rg", "eastus").CreateVM(context.Background(),
		VMOptions{Name: "n", Spot: true, Tags: map[string]string{"dispatcher": "true"}})
	require.NoError(t, err)

	data := mustRead(t, argv)
	assert.Contains(t, data, "--priority Spot")
	assert.Contains(t, data, "--eviction-policy Delete")
	assert.Contains(t, data, "--max-price -1", "cap at on-demand price: evicted on capacity, not price")
}

func TestAWSCreateVM_SpotFlags(t *testing.T) {
	argv := stubCLI(t, "aws",
		"case \"$*\" in\n"+
			"  *describe-vpcs*) echo 'vpc-1' ;;\n"+
			"  *create-security-group*) echo 'sg-1' ;;\n"+
			"  *describe-instances*) echo '{\"Reservations\":[{\"Instances\":[{\"InstanceId\":\"i-1\",\"PublicIpAddress\":\"1.2.3.4\",\"State\":{\"Name\":\"running\"}}]}]}' ;;\n"+
			"  *) echo '{\"Instances\":[{\"InstanceId\":\"i-1\"}]}' ;;\n"+
			"esac\n")

	_, _ = NewAWSProvider("us-east-1").CreateVM(context.Background(),
		VMOptions{Name: "n", Image: "ami-123", InstanceType: "g5.xlarge", Spot: true,
			Tags: map[string]string{"dispatcher": "true"}})

	data := mustRead(t, argv)
	assert.Contains(t, data, "--instance-market-options")
	assert.Contains(t, data, "MarketType=spot")
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}
