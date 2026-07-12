package confidential

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

// TestHashInputs_DeterministicAndChangeSensitive: the same tree hashes the same,
// a content change changes the hash, and *_test.go is ignored (tests don't affect
// the built binary).
func TestHashInputs_DeterministicAndChangeSensitive(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "agent/a.go", "package agent\nfunc A() {}\n")
	writeFile(t, root, "agent/b.go", "package agent\nfunc B() {}\n")
	writeFile(t, root, "go.mod", "module x\n")

	h1, err := hashInputs(root, []string{"agent", "go.mod"}, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, h1)

	h2, err := hashInputs(root, []string{"agent", "go.mod"}, nil)
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "same tree hashes the same")

	// A test file must not change the hash.
	writeFile(t, root, "agent/a_test.go", "package agent\n// tests don't affect the binary\n")
	h3, err := hashInputs(root, []string{"agent", "go.mod"}, nil)
	require.NoError(t, err)
	assert.Equal(t, h1, h3, "_test.go is ignored")

	// A source change must change the hash.
	writeFile(t, root, "agent/a.go", "package agent\nfunc A() { println(1) }\n")
	h4, err := hashInputs(root, []string{"agent", "go.mod"}, nil)
	require.NoError(t, err)
	assert.NotEqual(t, h1, h4, "a source change changes the hash")
}

// TestHashInputs_MissingPathFailsClosed: a listed input path that doesn't exist is
// an error, not a silent skip — otherwise a rename/removal narrows the guard to
// cover nothing without any signal, and a wrong repo-root hashes an empty tree.
func TestHashInputs_MissingPathFailsClosed(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module x\n")

	_, err := hashInputs(root, []string{"agent", "go.mod"}, nil)
	require.Error(t, err, "a missing top-level input path errors")
	assert.Contains(t, err.Error(), "agent")

	// A present-but-empty input set (no files) is also an error, never the empty hash.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "empty"), 0o755))
	_, err = hashInputs(root, []string{"empty"}, nil)
	require.Error(t, err, "an empty input set errors rather than hashing nothing")
}

// TestInputsHash_ExcludesSiblingSubpackages: a target's agent hash covers the
// shared core + its own cloud subpackage, but not sibling clouds' subpackages, so
// editing an unrelated cloud's agent doesn't spuriously invalidate this pin.
func TestInputsHash_ExcludesSiblingSubpackages(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "internal/attest/agent/agent.go", "package agent\n")         // shared core
	writeFile(t, root, "internal/attest/agent/nitro/n.go", "package nitro\n")       // AWSNitro's own
	writeFile(t, root, "internal/attest/agent/azuresnp/a.go", "package azuresnp\n") // sibling (Azure)
	writeFile(t, root, "internal/attest/agent/azure/m.go", "package azure\n")       // sibling (MAA)
	writeFile(t, root, "cmd/dispatcher-attest-nitro/main.go", "package main\n")
	writeFile(t, root, "cmd/dispatcher-nitro-proxy/main.go", "package main\n")
	writeFile(t, root, "deploy/nitro/Dockerfile", "FROM x\n")
	writeFile(t, root, "go.mod", "module x\n")
	writeFile(t, root, "go.sum", "\n")

	h1, err := InputsHash(root, AWSNitro)
	require.NoError(t, err)

	// Editing a sibling cloud's agent must NOT change the Nitro hash.
	writeFile(t, root, "internal/attest/agent/azuresnp/a.go", "package azuresnp\nvar x = 1\n")
	h2, err := InputsHash(root, AWSNitro)
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "a sibling subpackage edit doesn't invalidate this pin")

	// Editing the shared core or its own subpackage MUST change it.
	writeFile(t, root, "internal/attest/agent/nitro/n.go", "package nitro\nvar y = 1\n")
	h3, err := InputsHash(root, AWSNitro)
	require.NoError(t, err)
	assert.NotEqual(t, h1, h3, "its own subpackage edit invalidates the pin")
}

// TestHashInputs_DetectsRenameAndContentSwap: the path is folded into the digest,
// so renaming a file or swapping two files' contents changes the hash even though
// the byte multiset is identical — a tamper the guard must catch.
func TestHashInputs_DetectsRenameAndContentSwap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "agent/a.go", "package agent\n// A\n")
	writeFile(t, root, "agent/b.go", "package agent\n// B\n")
	writeFile(t, root, "go.mod", "module x\n")
	base, err := hashInputs(root, []string{"agent", "go.mod"}, nil)
	require.NoError(t, err)

	// Content swap: same bytes, different files.
	writeFile(t, root, "agent/a.go", "package agent\n// B\n")
	writeFile(t, root, "agent/b.go", "package agent\n// A\n")
	swapped, err := hashInputs(root, []string{"agent", "go.mod"}, nil)
	require.NoError(t, err)
	assert.NotEqual(t, base, swapped, "swapping two files' contents changes the hash")

	// Rename: same content under a new path.
	root2 := t.TempDir()
	writeFile(t, root2, "agent/a.go", "package agent\n// A\n")
	writeFile(t, root2, "go.mod", "module x\n")
	h1, err := hashInputs(root2, []string{"agent", "go.mod"}, nil)
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(root2, "agent/a.go")))
	writeFile(t, root2, "agent/c.go", "package agent\n// A\n")
	h2, err := hashInputs(root2, []string{"agent", "go.mod"}, nil)
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "renaming a file changes the hash")
}

// TestCheckPins_PerTargetAndMultiStale: a GCP pin is skipped even with a recorded
// hash (no static inputs); an Azure-only input change marks only azure-snp stale;
// a shared-core change marks both measured targets stale, returned in sorted order.
func TestCheckPins_PerTargetAndMultiStale(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "internal/attest/agent/agent.go", "package agent\n")
	writeFile(t, root, "internal/attest/agent/nitro/n.go", "package nitro\n")
	writeFile(t, root, "internal/attest/agent/azuresnp/a.go", "package azuresnp\n")
	writeFile(t, root, "cmd/dispatcher-attest-nitro/main.go", "package main\n")
	writeFile(t, root, "cmd/dispatcher-nitro-proxy/main.go", "package main\n")
	writeFile(t, root, "cmd/dispatcher-attest-azuresnp/main.go", "package main\n")
	writeFile(t, root, "deploy/nitro/Dockerfile", "FROM x\n")
	writeFile(t, root, "deploy/azure-uki/mkosi/mkosi.conf", "[Distribution]\n")
	writeFile(t, root, "go.mod", "module x\n")
	writeFile(t, root, "go.sum", "\n")

	nitroHash, err := InputsHash(root, AWSNitro)
	require.NoError(t, err)
	azHash, err := InputsHash(root, AzureSNP)
	require.NoError(t, err)

	reg := &Registry{}
	reg.Set(AWSNitro, Pin{InputsHash: nitroHash})
	reg.Set(AzureSNP, Pin{InputsHash: azHash})
	reg.Set(GCP, Pin{Image: "r@sha256:x", Measurement: "sha256:x", InputsHash: "ignored"}) // no static inputs

	stale, err := CheckPins(reg, root)
	require.NoError(t, err)
	assert.Empty(t, stale, "all current; GCP is skipped despite carrying a hash")

	// An Azure-only input change marks only azure-snp stale.
	writeFile(t, root, "deploy/azure-uki/mkosi/mkosi.conf", "[Distribution]\nchanged\n")
	stale, err = CheckPins(reg, root)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Equal(t, AzureSNP, stale[0].Target)

	// A shared-core change marks both, in sorted order (aws-nitro < azure-snp).
	writeFile(t, root, "internal/attest/agent/agent.go", "package agent\nvar z = 1\n")
	stale, err = CheckPins(reg, root)
	require.NoError(t, err)
	require.Len(t, stale, 2)
	assert.Equal(t, AWSNitro, stale[0].Target)
	assert.Equal(t, AzureSNP, stale[1].Target)
}

// TestMeasurementInputs_CoverBinaryImportClosure guards the hand-maintained input
// lists against silent drift. Every internal/ package actually linked into a
// target's measured binary must be covered by its measurementInputs and not wrongly
// excluded — so if a future refactor makes an agent import a new internal package
// (which would change the built measurement), this fails until the list is updated,
// rather than the guard silently ceasing to cover a real build input. It also
// catches an over-broad exclude that drops a linked subpackage.
func TestMeasurementInputs_CoverBinaryImportClosure(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	const mod = "github.com/d0cd/dispatcher/"
	targetCmds := map[Target][]string{
		AWSNitro: {"cmd/dispatcher-attest-nitro", "cmd/dispatcher-nitro-proxy"},
		AzureSNP: {"cmd/dispatcher-attest-azuresnp"},
	}
	for target, cmds := range targetCmds {
		for _, cmd := range cmds {
			// The agents are linux-only; resolve their build's import closure.
			c := exec.Command("go", "list", "-deps", mod+cmd)
			c.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
			out, err := c.Output()
			require.NoErrorf(t, err, "go list -deps %s", cmd)

			for _, dep := range strings.Fields(string(out)) {
				rel, ok := strings.CutPrefix(dep, mod)
				if !ok || !strings.HasPrefix(rel, "internal/") {
					continue
				}
				assert.Truef(t, inputCovers(target, rel),
					"%s links %s but measurementInputs[%s] does not cover it — update the input list or the exclude",
					cmd, rel, target)
			}
		}
	}
}

// inputCovers reports whether a repo-relative package path is under one of a
// target's measurement inputs and not under one of its excludes.
func inputCovers(target Target, rel string) bool {
	under := func(paths []string) bool {
		for _, p := range paths {
			if rel == p || strings.HasPrefix(rel, p+"/") {
				return true
			}
		}
		return false
	}
	return under(measurementInputs[target]) && !under(measurementInputExclude[target])
}

// TestInputsHash_PerTarget: the measured targets have a non-empty input set; GCP
// (measured per-run) has none.
func TestInputsHash_PerTarget(t *testing.T) {
	root := t.TempDir()
	// minimal stand-ins for the real repo paths
	writeFile(t, root, "internal/attest/agent/agent.go", "package agent\n")
	writeFile(t, root, "cmd/dispatcher-attest-nitro/main.go", "package main\n")
	writeFile(t, root, "cmd/dispatcher-nitro-proxy/main.go", "package main\n")
	writeFile(t, root, "cmd/dispatcher-attest-azuresnp/main.go", "package main\n")
	writeFile(t, root, "deploy/nitro/Dockerfile", "FROM x\n")
	writeFile(t, root, "deploy/azure-uki/mkosi/mkosi.conf", "[Distribution]\n")
	writeFile(t, root, "go.mod", "module x\n")
	writeFile(t, root, "go.sum", "\n")

	nitro, err := InputsHash(root, AWSNitro)
	require.NoError(t, err)
	assert.NotEmpty(t, nitro)

	az, err := InputsHash(root, AzureSNP)
	require.NoError(t, err)
	assert.NotEmpty(t, az)

	gcp, err := InputsHash(root, GCP)
	require.NoError(t, err)
	assert.Empty(t, gcp, "GCP is measured per-run — no static inputs to pin")
}

// TestCheckPins: a pin whose recorded inputs hash no longer matches the tree is
// reported stale; a matching one is not; a pin with no recorded hash is skipped.
func TestCheckPins(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "internal/attest/agent/agent.go", "package agent\n")
	writeFile(t, root, "cmd/dispatcher-attest-nitro/main.go", "package main\n")
	writeFile(t, root, "cmd/dispatcher-nitro-proxy/main.go", "package main\n")
	writeFile(t, root, "deploy/nitro/Dockerfile", "FROM x\n")
	writeFile(t, root, "go.mod", "module x\n")
	writeFile(t, root, "go.sum", "\n")

	cur, err := InputsHash(root, AWSNitro)
	require.NoError(t, err)

	reg := &Registry{}
	reg.Set(AWSNitro, Pin{Image: "/eif", Measurement: "pcr0", InputsHash: cur}) // fresh
	reg.Set(AzureSNP, Pin{Image: "/img", Measurement: "pcr11"})                 // no hash -> skipped

	stale, err := CheckPins(reg, root)
	require.NoError(t, err)
	assert.Empty(t, stale, "a matching pin and an unrecorded pin are not stale")

	// Change the agent source: the nitro pin is now stale.
	writeFile(t, root, "internal/attest/agent/agent.go", "package agent\nvar changed = true\n")
	stale, err = CheckPins(reg, root)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Equal(t, AWSNitro, stale[0].Target)
}
