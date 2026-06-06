package planner

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/d0cd/dispatcher/internal/cloudvm"
	"github.com/d0cd/dispatcher/internal/cost"
	"github.com/d0cd/dispatcher/internal/target"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newScopedRegistry(t *testing.T, root string) *ToolRegistry {
	t.Helper()
	reg := target.NewRegistry()
	hist, _ := cost.NewHistoryStore()
	cat := cloudvm.NewCatalog()
	tr := NewToolRegistry(reg, hist, cat)
	require.NoError(t, tr.SetWorkloadRoot(root))
	return tr
}

func TestInspectWorkload_RejectsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.py"), []byte("x=1"), 0o644))

	outside := t.TempDir() // a completely different temp dir
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("oops"), 0o644))

	tr := newScopedRegistry(t, root)

	cases := []struct {
		name string
		path string
	}{
		{"absolute-outside-tempdir", outside},
		{"absolute-etc-passwd", "/etc/passwd"},
		{"relative-traversal", "../../../etc/passwd"},
		{"sneaky-double-traversal", "subdir/../../" + filepath.Base(outside)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := tr.Execute(ToolCall{
				Name:  "inspect_workload",
				Input: mustJSON(map[string]string{"path": c.path}),
			}, nil)
			assert.NotEmpty(t, res.Error, "inspecting %q must error", c.path)
			assert.Contains(t, res.Error, "outside the workload root")
		})
	}
}

func TestInspectWorkload_AllowsRootAndChildren(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "main.py"), []byte("x=1"), 0o644))

	tr := newScopedRegistry(t, root)

	res := tr.Execute(ToolCall{
		Name:  "inspect_workload",
		Input: mustJSON(map[string]string{"path": sub}),
	}, nil)
	assert.Empty(t, res.Error, "subdir under the root must be allowed")
}

func TestInspectWorkload_EmptyPathDefaultsToRoot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.py"), []byte("x=1"), 0o644))

	tr := newScopedRegistry(t, root)

	res := tr.Execute(ToolCall{
		Name:  "inspect_workload",
		Input: mustJSON(map[string]string{}),
	}, nil)
	assert.Empty(t, res.Error)
}

func TestInspectWorkload_NoScopeRefuses(t *testing.T) {
	reg := target.NewRegistry()
	hist, _ := cost.NewHistoryStore()
	cat := cloudvm.NewCatalog()
	tr := NewToolRegistry(reg, hist, cat)

	res := tr.Execute(ToolCall{
		Name:  "inspect_workload",
		Input: mustJSON(map[string]string{"path": "/etc/passwd"}),
	}, nil)
	assert.Contains(t, res.Error, "workload root not configured")
}

// Race detector flags an unsynchronized version even though the test
// asserts only that the loop completes. Mostly here for `go test -race`.
func TestToolRegistry_SetWorkloadRootRace(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()

	reg := target.NewRegistry()
	hist, _ := cost.NewHistoryStore()
	cat := cloudvm.NewCatalog()
	tr := NewToolRegistry(reg, hist, cat)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = tr.SetWorkloadRoot(rootA)
			_ = tr.WorkloadRoot()
		}()
		go func() {
			defer wg.Done()
			_ = tr.SetWorkloadRoot(rootB)
			_, _ = tr.resolveWorkloadPath("")
		}()
	}
	wg.Wait()

	// Final state is one of the two roots (SetWorkloadRoot canonicalizes
	// via EvalSymlinks, so /tmp/... on macOS becomes /private/tmp/...).
	// The test's purpose is to flush the race detector, not to assert
	// ordering — that the loop ran to completion without -race firing
	// is what matters.
	got := tr.WorkloadRoot()
	canonA, _ := filepath.EvalSymlinks(rootA)
	canonB, _ := filepath.EvalSymlinks(rootB)
	assert.True(t, got == canonA || got == canonB,
		"final root should be one of the (canonicalized) inputs, got %q", got)
}
