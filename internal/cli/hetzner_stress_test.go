//go:build hetznere2e

// Opt-in live-provider stress lane. Provisions a REAL Hetzner VM, so it is gated
// behind the hetznere2e build tag and only runs in the scheduled/manual CI job
// (or locally with `hcloud` authenticated). It exercises the reliability
// invariants end-to-end on real hardware: a CPU-saturating job runs to
// completion under saturation (control-plane headroom + watchdog renewal held),
// its declared output is retrieved (artifact recovery), live cost is billed
// (budget accounting), and teardown leaves zero residual.
//
//   HCLOUD_TOKEN=... go test -tags hetznere2e -run TestHetznerStress ./internal/cli/
package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHetznerStress(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// A CPU-saturating job (~30s on every core) that writes a declared output.
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "main.sh"), []byte(
		"#!/bin/sh\n"+
			"echo start; i=0\n"+
			"while [ \"$i\" -lt \"$(nproc)\" ]; do yes > /dev/null & i=$((i+1)); done\n"+
			"sleep 30\n"+
			"kill $(jobs -p) 2>/dev/null\n"+
			"echo \"done cores=$(nproc)\" > result.txt\n"+
			"echo complete\n"), 0o755))

	planID := "plan_hetznerstress_" + types.ShortID()
	plan := &types.Plan{
		Metadata: types.PlanMetadata{ID: planID, CreatedAt: time.Now().UTC(), CreatedBy: "hetznere2e"},
		Workload: types.WorkloadSpec{
			Name:         "stress",
			Source:       types.WorkloadSource{Path: src},
			Command:      []string{"sh", "main.sh"},
			Outputs:      []string{"result.txt"},
			DetectedKind: types.WorkloadKindScript,
		},
		Constraints: types.PlanConstraints{MaxEstimatedCostUSD: 0.50, MaxDuration: 8 * time.Minute},
		Recommendation: &types.Recommendation{
			Target:        "hetzner-vm",
			EstimatedCost: types.CostEstimate{Value: 0.01, Currency: "USD", Confidence: types.ConfidenceMedium},
		},
	}

	provider := cloudvm.NewHetznerProvider("")
	adapter := cloudvm.NewCloudVMAdapter(provider, cloudvm.Config{ProviderID: cloudvm.ProviderHetzner})
	ex := run.NewExecutor(adapter)
	ex.SetApprovalFunc(yesApproval)
	r := run.NewRun(plan)

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	// Safety net: if the run panics or leaves a VM, reap it by the run-id tag so a
	// failed lane never leaks a billing server.
	defer func() {
		if vms, err := provider.ListVMs(context.Background(), map[string]string{"dispatcher-run-id": planID}); err == nil {
			for _, vm := range vms {
				_ = provider.DestroyVM(context.Background(), vm.ID)
			}
		}
	}()

	require.NoError(t, ex.Execute(ctx, r, os.Stderr), "the CPU-saturating run must complete on real hardware")

	// Control-plane headroom + watchdog renewal held: the run reached Completed.
	assert.Equal(t, types.RunStateCompleted, r.GetState())
	// Artifact recovery: the declared output was retrieved.
	assert.NotEmpty(t, r.Artifacts, "the declared output must be retrieved before teardown")
	// Budget accounting: live cost was billed, not $0.00.
	assert.Greater(t, r.Cost.Value, 0.0, "the run must bill non-zero cost")

	// Zero residual: no server tagged for this run survives teardown.
	vms, err := provider.ListVMs(context.Background(), map[string]string{"dispatcher-run-id": planID})
	require.NoError(t, err)
	assert.Empty(t, vms, "teardown must leave no residual server")
}
