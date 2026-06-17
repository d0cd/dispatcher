//go:build k8se2e

// Package cloudvm e2e tests exercise the real K8sAdapter against a live cluster.
//
// They are excluded from the normal suite (build tag k8se2e) because they need a
// reachable Kubernetes cluster. Run them with, e.g.:
//
//	colima start --kubernetes
//	go test -tags k8se2e -run TestK8sE2E -timeout 8m ./internal/cloudvm/
//
// They validate the parts that can't be unit-tested: the init-container source
// handoff, and that the Job's status/exit code reflect the real workload (the
// whole point of running the workload as the Job's main container).
package cloudvm

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
	"github.com/d0cd/dispatcher/internal/types"
)

func requireCluster(t *testing.T) {
	t.Helper()
	if err := exec.Command("kubectl", "cluster-info").Run(); err != nil {
		t.Skipf("no reachable kubernetes cluster: %v", err)
	}
}

func k8sPlan(name string, command []string, sourcePath string) *types.Plan {
	return &types.Plan{
		Metadata: types.PlanMetadata{ID: name},
		Workload: types.WorkloadSpec{
			Name:    name,
			Command: command,
			Source:  types.WorkloadSource{Path: sourcePath},
		},
		Recommendation: &types.Recommendation{Target: "kubernetes"},
	}
}

// waitForTerminal polls Status until the run reaches a terminal state or times out.
func waitForTerminal(t *testing.T, a *K8sAdapter, h *adapter.RunHandle, timeout time.Duration) types.RunState {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last types.RunState
	for time.Now().Before(deadline) {
		st, err := a.Status(context.Background(), h)
		require.NoError(t, err)
		last = st
		if st.IsTerminal() {
			return st
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("run did not reach a terminal state within %s (last: %s)", timeout, last)
	return last
}

// A successful workload must report Completed, and its stdout must reach the log.
func TestK8sE2E_SuccessfulWorkload(t *testing.T) {
	requireCluster(t)
	a := NewK8sAdapter("default")
	ctx := context.Background()

	// Echo a marker, then linger briefly so logs are catchable while running.
	h, err := a.Execute(ctx, k8sPlan("e2e-ok",
		[]string{"sh", "-c", "echo DISPATCHER_E2E_MARKER; sleep 8; exit 0"}, ""))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = a.Cleanup(context.Background(), h) })

	// Best-effort: catch the log while the pod is still up.
	var gotMarker bool
	for i := 0; i < 6; i++ {
		var logs bytes.Buffer
		if a.Logs(ctx, h, &logs) == nil && strings.Contains(logs.String(), "DISPATCHER_E2E_MARKER") {
			gotMarker = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	assert.True(t, gotMarker, "workload stdout should reach /workspace/dispatcher.log")

	assert.Equal(t, types.RunStateCompleted, waitForTerminal(t, a, h, 3*time.Minute),
		"a successful workload must report Completed")
}

// A failing workload must report ExecutionFailed with the real exit code — the
// core proof that the Job tracks the workload, not a keep-alive container.
func TestK8sE2E_FailingWorkload(t *testing.T) {
	requireCluster(t)
	a := NewK8sAdapter("default")
	ctx := context.Background()

	h, err := a.Execute(ctx, k8sPlan("e2e-fail", []string{"sh", "-c", "exit 7"}, ""))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = a.Cleanup(context.Background(), h) })

	require.Equal(t, types.RunStateExecutionFailed, waitForTerminal(t, a, h, 3*time.Minute),
		"a failing workload must report ExecutionFailed")
	assert.Equal(t, 7, a.FailureDetails(h).ExitCode,
		"FailureDetails must report the real workload exit code")
}

// Source files must be delivered into the workload's working dir by the init
// container; the workload verifies the content via its exit code.
func TestK8sE2E_SourceDelivery(t *testing.T) {
	requireCluster(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "marker.txt"), []byte("OK"), 0o644))

	a := NewK8sAdapter("default")
	ctx := context.Background()

	h, err := a.Execute(ctx, k8sPlan("e2e-src",
		[]string{"sh", "-c", `[ "$(cat marker.txt)" = "OK" ] && exit 0 || exit 9`}, dir))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = a.Cleanup(context.Background(), h) })

	assert.Equal(t, types.RunStateCompleted, waitForTerminal(t, a, h, 3*time.Minute),
		"the workload must find its source files at /workspace (exit 9 means they weren't delivered)")
}
