package target

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

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
