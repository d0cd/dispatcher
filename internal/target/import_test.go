package target

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

// stubRunTF replaces the runTF seam so the terraform output path can be tested
// without a real binary.
func stubRunTF(t *testing.T, fn func(ctx context.Context, binary, dir, workspace string) (stdout, stderr []byte, err error)) {
	t.Helper()
	prev := runTF
	runTF = fn
	t.Cleanup(func() { runTF = prev })
}

func TestFetchTerraformTargets_ExtractsEnvelopeValue(t *testing.T) {
	stubRunTF(t, func(_ context.Context, _, _, _ string) ([]byte, []byte, error) {
		return []byte(`{"dispatcher_targets":{"sensitive":false,"type":["object",{}],"value":{"targets":[{"id":"a","kind":"ssh","ssh":{"host":"h"}}]}}}`), nil, nil
	})
	blob, err := FetchTerraformTargets(context.Background(), "/x", TerraformOptions{Binary: "terraform"})
	require.NoError(t, err)
	got, err := ParseDispatcherTargets(blob)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "a", got[0].ID)
}

func TestFetchTerraformTargets_NoOutputIsSentinel(t *testing.T) {
	stubRunTF(t, func(_ context.Context, _, _, _ string) ([]byte, []byte, error) { return []byte(`{}`), nil, nil })
	_, err := FetchTerraformTargets(context.Background(), "/x", TerraformOptions{})
	assert.ErrorIs(t, err, ErrNoTargetsOutput)
}

func TestFetchTerraformTargets_SensitiveRefusedUnlessAllowed(t *testing.T) {
	blob := `{"dispatcher_targets":{"sensitive":true,"value":{"targets":[]}}}`
	stubRunTF(t, func(_ context.Context, _, _, _ string) ([]byte, []byte, error) { return []byte(blob), nil, nil })

	_, err := FetchTerraformTargets(context.Background(), "/x", TerraformOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sensitive")

	_, err = FetchTerraformTargets(context.Background(), "/x", TerraformOptions{AllowSensitive: true})
	require.NoError(t, err)
}

func TestFetchTerraformTargets_ExecErrorWrapped(t *testing.T) {
	stubRunTF(t, func(_ context.Context, _, _, _ string) ([]byte, []byte, error) { return nil, nil, assert.AnError })
	_, err := FetchTerraformTargets(context.Background(), "/x", TerraformOptions{Binary: "terraform"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terraform")
}

func TestFetchTerraformTargets_InitHintNoStderrLeak(t *testing.T) {
	stubRunTF(t, func(_ context.Context, _, _, _ string) ([]byte, []byte, error) {
		return nil, []byte(`Error: Backend initialization required, please run "terraform init"`), assert.AnError
	})
	_, err := FetchTerraformTargets(context.Background(), "/x", TerraformOptions{Binary: "terraform"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terraform init", "should give an actionable hint")
	assert.NotContains(t, err.Error(), "Backend initialization", "raw stderr must not be echoed")
}

func TestFetchTerraformTargets_WorkspacePassedThrough(t *testing.T) {
	var gotWS string
	stubRunTF(t, func(_ context.Context, _, _, ws string) ([]byte, []byte, error) {
		gotWS = ws
		return []byte(`{}`), nil, nil
	})
	_, _ = FetchTerraformTargets(context.Background(), "/x", TerraformOptions{Workspace: "staging"})
	assert.Equal(t, "staging", gotWS)
}

func TestParseDispatcherTargets_ExpandsKeyFileTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := ParseDispatcherTargets([]byte(`{"targets":[{"id":"x","kind":"ssh","ssh":{"host":"h","key_file":"~/.ssh/id"}}]}`))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, filepath.Join(home, ".ssh/id"), got[0].SSH.KeyFile, "leading ~ must expand to an absolute path")
}

func TestKeyFileWarnings(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	require.NoError(t, os.WriteFile(good, []byte("k"), 0o600))
	bad := filepath.Join(dir, "bad")
	require.NoError(t, os.WriteFile(bad, []byte("k"), 0o644))

	warns := KeyFileWarnings([]types.TargetConfig{
		{ID: "ok", SSH: &types.SSHTargetConfig{Host: "h", KeyFile: good}},
		{ID: "perm", SSH: &types.SSHTargetConfig{Host: "h", KeyFile: bad}},
		{ID: "missing", SSH: &types.SSHTargetConfig{Host: "h", KeyFile: filepath.Join(dir, "nope")}},
		{ID: "nokey", SSH: &types.SSHTargetConfig{Host: "h"}},
	})
	require.Len(t, warns, 2)
	joined := strings.Join(warns, "\n")
	assert.Contains(t, joined, "does not exist")
	assert.Contains(t, joined, "accessible")
}

func TestPlanImport_DoesNotWriteUntilCommit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	plan, err := PlanImport([]byte(`{"targets":[{"id":"a","kind":"ssh","ssh":{"host":"h"}}]}`))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a"}, plan.Added)
	assert.True(t, plan.HasChanges())

	reg := NewRegistry()
	require.NoError(t, reg.LoadUserConfig())
	_, ok := reg.Get("a")
	assert.False(t, ok, "PlanImport must not write anything")

	_, err = plan.Commit()
	require.NoError(t, err)
	reg2 := NewRegistry()
	require.NoError(t, reg2.LoadUserConfig())
	_, ok = reg2.Get("a")
	assert.True(t, ok, "Commit must persist the plan")
}

func TestDefaultCapabilities(t *testing.T) {
	for _, k := range []types.TargetKind{
		types.TargetKindDocker, types.TargetKindSSH, types.TargetKindKubernetes, types.TargetKindLocal,
	} {
		assert.NotEmpty(t, DefaultCapabilities(k).WorkloadKinds, "kind %s must advertise workload kinds", k)
	}
	assert.True(t, DefaultCapabilities(types.TargetKindKubernetes).Resources.GPU.Supported)
	assert.True(t, DefaultCapabilities(types.TargetKindSSH).Networking.PublicEndpoint)
}

func TestParseDispatcherTargets_Valid(t *testing.T) {
	blob := []byte(`{"targets":[{"id":"trainer","kind":"ssh","ssh":{"host":"203.0.113.10","user":"ubuntu","port":2222,"key_file":"/home/me/.ssh/id"}}]}`)
	got, err := ParseDispatcherTargets(blob)
	require.NoError(t, err)
	require.Len(t, got, 1)

	tc := got[0]
	assert.Equal(t, "trainer", tc.ID)
	assert.Equal(t, types.TargetKindSSH, tc.Kind)
	assert.True(t, tc.Enabled, "imported targets must be enabled or the planner drops them as infeasible")
	require.NotNil(t, tc.SSH)
	assert.Equal(t, "203.0.113.10", tc.SSH.Host)
	assert.Equal(t, 2222, tc.SSH.Port)
	assert.NotEmpty(t, tc.Capabilities.WorkloadKinds, "must carry capabilities or it is infeasible")
}

func TestParseDispatcherTargets_DefaultsPort22(t *testing.T) {
	got, err := ParseDispatcherTargets([]byte(`{"targets":[{"id":"x","kind":"ssh","ssh":{"host":"h"}}]}`))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, 22, got[0].SSH.Port)
}

func TestParseDispatcherTargets_EmptyListOK(t *testing.T) {
	got, err := ParseDispatcherTargets([]byte(`{"targets":[]}`))
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestParseDispatcherTargets_Rejects(t *testing.T) {
	cases := map[string]string{
		"non-ssh kind":     `{"targets":[{"id":"x","kind":"kubernetes","ssh":{"host":"h"}}]}`,
		"duplicate ids":    `{"targets":[{"id":"x","kind":"ssh","ssh":{"host":"h"}},{"id":"x","kind":"ssh","ssh":{"host":"h2"}}]}`,
		"reserved builtin": `{"targets":[{"id":"aws-vm","kind":"ssh","ssh":{"host":"h"}}]}`,
		"unsafe host":      `{"targets":[{"id":"x","kind":"ssh","ssh":{"host":"-oProxyCommand=x"}}]}`,
		"traversal id":     `{"targets":[{"id":"../x","kind":"ssh","ssh":{"host":"h"}}]}`,
		"empty id":         `{"targets":[{"id":"","kind":"ssh","ssh":{"host":"h"}}]}`,
		"missing ssh":      `{"targets":[{"id":"x","kind":"ssh"}]}`,
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDispatcherTargets([]byte(blob))
			assert.Error(t, err)
		})
	}
}

func TestParseDispatcherTargets_MalformedJSON(t *testing.T) {
	_, err := ParseDispatcherTargets([]byte(`not json`))
	assert.Error(t, err)
}

func TestImportFromJSON_AddUpdateRemove(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	r1, err := ImportFromJSON([]byte(`{"targets":[
		{"id":"a","kind":"ssh","ssh":{"host":"ha"}},
		{"id":"b","kind":"ssh","ssh":{"host":"hb"}}]}`))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a", "b"}, r1.Added)
	assert.Empty(t, r1.Removed)

	// Re-import: a updated, c added, b removed.
	r2, err := ImportFromJSON([]byte(`{"targets":[
		{"id":"a","kind":"ssh","ssh":{"host":"ha2"}},
		{"id":"c","kind":"ssh","ssh":{"host":"hc"}}]}`))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a"}, r2.Updated)
	assert.ElementsMatch(t, []string{"c"}, r2.Added)
	assert.ElementsMatch(t, []string{"b"}, r2.Removed)

	reg := NewRegistry()
	require.NoError(t, reg.LoadUserConfig())
	_, ok := reg.Get("a")
	assert.True(t, ok)
	_, ok = reg.Get("c")
	assert.True(t, ok)
	_, ok = reg.Get("b")
	assert.False(t, ok, "removed target must be gone after re-import")
}

func TestImportFromJSON_RejectsHandAddedCollision(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := SaveTarget(types.TargetConfig{
		ID: "box", Kind: types.TargetKindSSH, Enabled: true,
		SSH: &types.SSHTargetConfig{Host: "h"},
	})
	require.NoError(t, err)

	_, err = ImportFromJSON([]byte(`{"targets":[{"id":"box","kind":"ssh","ssh":{"host":"h2"}}]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hand-added")
}

func TestImportFromJSON_EmptyDeletesAll(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := ImportFromJSON([]byte(`{"targets":[{"id":"a","kind":"ssh","ssh":{"host":"h"}}]}`))
	require.NoError(t, err)

	r, err := ImportFromJSON([]byte(`{"targets":[]}`))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a"}, r.Removed)

	reg := NewRegistry()
	require.NoError(t, reg.LoadUserConfig())
	_, ok := reg.Get("a")
	assert.False(t, ok)
}

func TestWriteTargetsFile_AtomicRoundTripAndWholesale(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	path, err := WriteTargetsFile("terraform-import.yaml", []types.TargetConfig{
		{ID: "a", Kind: types.TargetKindSSH, Enabled: true, SSH: &types.SSHTargetConfig{Host: "h"}},
	})
	require.NoError(t, err)
	assert.Contains(t, path, "terraform-import.yaml")

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "managed target file must be 0600")

	r := NewRegistry()
	require.NoError(t, r.LoadFromFile(path))
	_, ok := r.Get("a")
	assert.True(t, ok)

	// Re-import regenerates wholesale: an empty set removes everything.
	_, err = WriteTargetsFile("terraform-import.yaml", nil)
	require.NoError(t, err)
	r2 := NewRegistry()
	require.NoError(t, r2.LoadFromFile(path))
	_, ok = r2.Get("a")
	assert.False(t, ok, "rewrite must replace the file's contents wholesale")
}

func TestWriteTargetsFile_RejectsUnsafeTarget(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := WriteTargetsFile("terraform-import.yaml", []types.TargetConfig{
		{ID: "x", Kind: types.TargetKindSSH, SSH: &types.SSHTargetConfig{Host: "a@b"}},
	})
	require.Error(t, err, "the persist choke point must re-validate ssh fields")
}
