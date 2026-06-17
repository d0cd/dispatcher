package target

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `targets:
  - id: custom-k8s
    kind: kubernetes
    enabled: true
    capabilities:
      workloadKinds:
        - job
        - service
      resources:
        cpu: true
        memory: true
        gpu:
          supported: false
      networking:
        publicEndpoint: true
        privateVpcAccess: true
        staticEgressIp: false
      accounting:
        costEstimate: true
        actualBilling: false
        rateCard: internal
      isolation:
        levels:
          - container
      observability:
        logs: true
        metrics: true
        artifacts: true
`
	path := filepath.Join(dir, "targets.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o644))

	r := NewRegistry()
	require.NoError(t, r.LoadFromFile(path))

	target, ok := r.Get("custom-k8s")
	assert.True(t, ok)
	assert.Equal(t, types.TargetKindKubernetes, target.Kind)
	assert.True(t, target.Enabled)
	assert.True(t, target.Capabilities.Networking.PublicEndpoint)
}

func TestLoadFromFile_MissingID(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `targets:
  - kind: docker
    enabled: true
`
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o644))

	r := NewRegistry()
	err := r.LoadFromFile(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required field 'id'")
}

func TestLoadFromDir(t *testing.T) {
	dir := t.TempDir()

	// Write two target files
	file1 := `targets:
  - id: target-a
    kind: docker
    enabled: true
`
	file2 := `targets:
  - id: target-b
    kind: ssh
    enabled: true
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(file1), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.yml"), []byte(file2), 0o644))
	// Non-yaml file should be ignored
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("ignore me"), 0o644))

	r := NewRegistry()
	require.NoError(t, r.LoadFromDir(dir))

	_, ok := r.Get("target-a")
	assert.True(t, ok)
	_, ok = r.Get("target-b")
	assert.True(t, ok)
}

func TestLoadFromDir_NonExistent(t *testing.T) {
	r := NewRegistry()
	err := r.LoadFromDir("/nonexistent/path")
	assert.NoError(t, err) // should not error on missing dir
}

func TestLoadFromFile_OverridesBuiltin(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `targets:
  - id: local-docker
    kind: docker
    enabled: false
`
	path := filepath.Join(dir, "override.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o644))

	r := NewRegistry()
	r.LoadBuiltins()

	// Before: enabled
	target, _ := r.Get("local-docker")
	assert.True(t, target.Enabled)

	// After override: disabled
	require.NoError(t, r.LoadFromFile(path))
	target, _ = r.Get("local-docker")
	assert.False(t, target.Enabled)
}

func TestSaveTarget(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	target := types.TargetConfig{
		ID:      "my-ssh-box",
		Kind:    types.TargetKindSSH,
		Enabled: true,
	}

	path, err := SaveTarget(target)
	require.NoError(t, err)
	assert.FileExists(t, path)
	assert.Contains(t, path, "my-ssh-box.yaml")

	// Verify it can be loaded back
	r := NewRegistry()
	require.NoError(t, r.LoadFromFile(path))
	loaded, ok := r.Get("my-ssh-box")
	assert.True(t, ok)
	assert.Equal(t, types.TargetKindSSH, loaded.Kind)
}

func TestDeleteTarget(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	saved := types.TargetConfig{ID: "removable", Kind: types.TargetKindSSH, Enabled: true}
	path, err := SaveTarget(saved)
	require.NoError(t, err)
	require.FileExists(t, path)

	removed, err := DeleteTarget("removable")
	require.NoError(t, err)
	assert.Equal(t, path, removed)
	assert.NoFileExists(t, path)
}

func TestDeleteTarget_NotFound(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := DeleteTarget("does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does-not-exist")
}

func TestDeleteTarget_RejectsTraversal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := DeleteTarget("../etc/passwd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path separator or traversal")
}

func TestLoadProjectConfig(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `targets:
  - id: project-target
    kind: docker
    enabled: true
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dispatcher.yaml"), []byte(yamlContent), 0o644))

	r := NewRegistry()
	require.NoError(t, r.LoadProjectConfig(dir))

	_, ok := r.Get("project-target")
	assert.True(t, ok)
}

func TestLoadProjectConfig_NoFile(t *testing.T) {
	r := NewRegistry()
	err := r.LoadProjectConfig(t.TempDir())
	assert.NoError(t, err) // no dispatcher.yaml is fine
}
