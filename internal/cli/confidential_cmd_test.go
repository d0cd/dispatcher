package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/confidential"
)

func TestParseTarget(t *testing.T) {
	for _, s := range []string{"gcp", "aws-nitro", "azure-snp"} {
		got, err := parseTarget(s)
		require.NoError(t, err)
		assert.Equal(t, confidential.Target(s), got)
	}
	_, err := parseTarget("sev-snp")
	require.Error(t, err, "an unknown target is rejected")
	assert.Contains(t, err.Error(), "gcp | aws-nitro | azure-snp")
}

func TestCaptureMeasurement_GCP(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	pin, err := captureMeasurement(confidential.GCP, "us-docker.pkg.dev/p/r@"+digest)
	require.NoError(t, err)
	assert.Equal(t, digest, pin.Measurement)

	_, err = captureMeasurement(confidential.GCP, "us-docker.pkg.dev/p/r:latest")
	require.Error(t, err, "a non-digest-pinned GCP image has no measurement")
}

// TestCaptureMeasurement_Nitro covers the aws-nitro capture branch: a read error, a
// valid describe-eif that yields PCR0 + the pinned eif/proxy, and a malformed PCR0.
func TestCaptureMeasurement_Nitro(t *testing.T) {
	_, err := captureMeasurement(confidential.AWSNitro, filepath.Join(t.TempDir(), "nope.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read nitro-cli output")

	dir := t.TempDir()
	pcr0 := strings.Repeat("84", 48) // 96 hex (SHA-384)
	src := filepath.Join(dir, "describe.json")
	require.NoError(t, os.WriteFile(src, []byte(`{"Measurements":{"PCR0":"`+pcr0+`"}}`), 0o644))

	confidentialCaptureFlags.eif = "/tmp/agent.eif"
	confidentialCaptureFlags.proxy = "/tmp/proxy"
	t.Cleanup(func() { confidentialCaptureFlags.eif = ""; confidentialCaptureFlags.proxy = "" })

	pin, err := captureMeasurement(confidential.AWSNitro, src)
	require.NoError(t, err)
	assert.Equal(t, pcr0, pin.Measurement)
	assert.Equal(t, "/tmp/agent.eif", pin.Image)
	assert.Equal(t, "/tmp/proxy", pin.Extra["proxy"])

	bad := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`{"Measurements":{"PCR0":"short"}}`), 0o644))
	_, err = captureMeasurement(confidential.AWSNitro, bad)
	require.Error(t, err, "a malformed PCR0 is rejected")
}

func TestBuildNitro_RequiresProxy(t *testing.T) {
	confidentialBuildFlags.proxy = ""
	err := buildNitro(&cobra.Command{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--proxy is required")
}

// TestRunConfidentialCheck: the drift guard passes when a pin's recorded inputs
// hash matches the tree, fails when it doesn't, and is a clean no-op with no pins.
func TestRunConfidentialCheck(t *testing.T) {
	repo := t.TempDir()
	writeCheckFile(t, repo, "internal/attest/agent/agent.go", "package agent\n")
	writeCheckFile(t, repo, "cmd/dispatcher-attest-nitro/main.go", "package main\n")
	writeCheckFile(t, repo, "cmd/dispatcher-nitro-proxy/main.go", "package main\n")
	writeCheckFile(t, repo, "deploy/nitro/Dockerfile", "FROM x\n")
	writeCheckFile(t, repo, "go.mod", "module x\n")
	writeCheckFile(t, repo, "go.sum", "\n")

	hash, err := confidential.InputsHash(repo, confidential.AWSNitro)
	require.NoError(t, err)

	pinsPath := filepath.Join(repo, "pins.yaml")
	reg := &confidential.Registry{}
	reg.Set(confidential.AWSNitro, confidential.Pin{Image: "/eif", Measurement: "pcr0", InputsHash: hash})
	require.NoError(t, reg.Save(pinsPath))

	var out bytes.Buffer
	require.NoError(t, runConfidentialCheck(&out, repo, pinsPath), "matching pin passes")

	// A missing pins file is a clean pass (nothing pinned yet).
	require.NoError(t, runConfidentialCheck(&out, repo, filepath.Join(repo, "none.yaml")))

	// Change the agent source: the pin is now stale and check must fail.
	writeCheckFile(t, repo, "internal/attest/agent/agent.go", "package agent\nvar changed = true\n")
	err = runConfidentialCheck(&out, repo, pinsPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws-nitro")
	assert.Contains(t, err.Error(), "re-capture")
}

func writeCheckFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

// nitroRepo writes a minimal source tree carrying the AWSNitro measurement inputs.
func nitroRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	writeCheckFile(t, repo, "internal/attest/agent/agent.go", "package agent\n")
	writeCheckFile(t, repo, "internal/attest/agent/nitro/n.go", "package nitro\n")
	writeCheckFile(t, repo, "cmd/dispatcher-attest-nitro/main.go", "package main\n")
	writeCheckFile(t, repo, "cmd/dispatcher-nitro-proxy/main.go", "package main\n")
	writeCheckFile(t, repo, "deploy/nitro/Dockerfile", "FROM x\n")
	writeCheckFile(t, repo, "go.mod", "module x\n")
	writeCheckFile(t, repo, "go.sum", "\n")
	return repo
}

// TestSavePin_RecordsInputsHashThenCheckDetectsDrift: savePin records the drift
// baseline (the mechanism the whole guard hinges on), and a later source change is
// caught by check — the end-to-end pin→check path, not a hand-injected hash.
func TestSavePin_RecordsInputsHashThenCheckDetectsDrift(t *testing.T) {
	repo := nitroRepo(t)
	pins := filepath.Join(t.TempDir(), "pins.yaml")

	err := savePin(&cobra.Command{}, confidential.AWSNitro,
		confidential.Pin{Image: "/eif", Measurement: "pcr0"}, repo, pins)
	require.NoError(t, err)

	reg, err := confidential.Load(pins)
	require.NoError(t, err)
	p, ok := reg.Get(confidential.AWSNitro)
	require.True(t, ok)
	want, err := confidential.InputsHash(repo, confidential.AWSNitro)
	require.NoError(t, err)
	assert.Equal(t, want, p.InputsHash)
	assert.NotEmpty(t, p.InputsHash, "the drift baseline is actually recorded")

	var out bytes.Buffer
	require.NoError(t, runConfidentialCheck(&out, repo, pins), "fresh pin is current")
	writeCheckFile(t, repo, "internal/attest/agent/agent.go", "package agent\nvar x = 1\n")
	require.Error(t, runConfidentialCheck(&out, repo, pins), "a source change is caught")
}

// TestSavePin_FailsClosedOffSourceTree: a repo-root that isn't the source tree can't
// be hashed, so savePin refuses rather than record a pin with no drift baseline
// (which check would silently skip forever).
func TestSavePin_FailsClosedOffSourceTree(t *testing.T) {
	notRepo := t.TempDir()
	err := savePin(&cobra.Command{}, confidential.AWSNitro,
		confidential.Pin{Image: "/eif", Measurement: "pcr0"}, notRepo, filepath.Join(notRepo, "pins.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "measurement inputs")
}

// TestConfidentialCheck_ExplicitMissingPinsErrors: an explicitly requested registry
// that is absent is a hard error, not an empty pass — a mistyped path or dropped
// commit can't read as "verified".
func TestConfidentialCheck_ExplicitMissingPinsErrors(t *testing.T) {
	confidentialCheckFlags.pins = filepath.Join(t.TempDir(), "nope.yaml")
	confidentialCheckFlags.repoRoot = "."
	t.Cleanup(func() { confidentialCheckFlags.pins = ""; confidentialCheckFlags.repoRoot = "." })

	err := confidentialCheckCmd.RunE(&cobra.Command{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestConfidentialBuild_GuidanceForNonNitro: gcp/azure have no single-host build,
// so `build` returns actionable guidance instead of pretending.
func TestConfidentialBuild_GuidanceForNonNitro(t *testing.T) {
	for _, tc := range []struct{ target, want string }{
		{"gcp", "per-run workload container"},
		{"azure-snp", "multi-host build"},
	} {
		err := confidentialBuildCmd.RunE(&cobra.Command{}, []string{tc.target})
		require.Error(t, err)
		assert.Contains(t, err.Error(), tc.want)
	}
}
