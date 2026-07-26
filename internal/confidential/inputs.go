package confidential

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// measurementInputs are the repo paths whose content determines a target's
// measurement: the agent source, the build config, and the dependency lockfiles.
// Change any of these and the built artifact — and its measurement — changes, so
// the pin must be re-captured. Keep this list small and explicit.
//
// NOT covered — re-capture periodically, or pin these in deploy/ to close the gap:
//   - The base image + kernel's floating package versions. The Nitro Dockerfile
//     bases are digest-pinned (FROM golang@sha256:… / alpine@sha256:…), but a
//     kernel/package bump inside the mkosi (azure-snp) image still moves PCR11
//     without changing our source; re-capture on a base bump.
//   - The exact Go toolchain. go.mod's `go` directive is a MINIMUM, so a patch bump
//     of the builder's toolchain changes the artifact without changing go.mod. Both
//     agents build in the digest-pinned golang container (Nitro via its Dockerfile,
//     azure-snp via deploy/azure-uki/mkosi/build-agent.sh), so the toolchain is a
//     hashed input, not the builder host's floating Go.
//
// GCP is measured per-run (the workload container), so it has no static inputs to pin.
var measurementInputs = map[Target][]string{
	AWSNitro: {
		"internal/attest/agent", // agent-core (linked into the enclave agent)
		"internal/attest/atls",  // attested-TLS transport the agent serves
		"cmd/dispatcher-attest-nitro",
		"cmd/dispatcher-nitro-proxy",
		"deploy/nitro",
		"go.mod", "go.sum",
	},
	AzureSNP: {
		"internal/attest/agent",
		"internal/attest/atls", // attested-TLS transport the agent serves
		"cmd/dispatcher-attest-azuresnp",
		"deploy/azure-uki/mkosi",
		"go.mod", "go.sum",
	},
}

// measurementInputExclude are sibling agent subpackages NOT linked into a target's
// binary (confirmed via the build's import closure), excluded from its hash so an
// unrelated cloud's agent edit doesn't spuriously invalidate this target's pin.
var measurementInputExclude = map[Target][]string{
	AWSNitro: {"internal/attest/agent/azuresnp"},
	AzureSNP: {"internal/attest/agent/nitro"},
}

// InputsHash hashes a target's measurement inputs under repoRoot. It returns an
// empty hash (no error) for targets with no static inputs (GCP). It fails closed:
// a missing input path or an empty input set is an error, never a silent hash of
// nothing — otherwise a rename, a removal, or a wrong repo-root would narrow the
// guard to cover nothing without any signal.
func InputsHash(repoRoot string, t Target) (string, error) {
	paths, ok := measurementInputs[t]
	if !ok {
		return "", nil
	}
	return hashInputs(repoRoot, paths, measurementInputExclude[t])
}

// hashInputs returns a deterministic content hash of the given repo-relative paths
// (files or directories, recursed), skipping anything under an exclude path. Test
// files (*_test.go) are ignored — they don't affect the built binary. A listed
// path that doesn't exist, or a resolved set with no files, is an error.
func hashInputs(repoRoot string, paths, exclude []string) (string, error) {
	excluded := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		excluded[filepath.Join(repoRoot, e)] = true
	}
	var files []string
	for _, rel := range paths {
		abs := filepath.Join(repoRoot, rel)
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("measurement input %q not found under %s: %w", rel, repoRoot, err)
		}
		err := filepath.Walk(abs, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if excluded[p] {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(p, "_test.go") {
				return nil
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no measurement input files found under %s for paths %v", repoRoot, paths)
	}
	sort.Strings(files)

	h := sha256.New()
	for _, p := range files {
		rel, _ := filepath.Rel(repoRoot, p)
		fmt.Fprintf(h, "%s\x00", filepath.ToSlash(rel)) // path so renames register
		f, err := os.Open(p)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			return "", err
		}
		f.Close()
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// StalePin is a pin whose recorded inputs hash no longer matches the current tree
// — the measured image needs a rebuild + re-capture + re-pin.
type StalePin struct {
	Target   Target
	Recorded string
	Current  string
}

// CheckPins reports pins whose measurement inputs changed since capture. Pins with
// no recorded InputsHash are skipped (nothing to compare), as are targets with no
// static inputs (GCP). This is the drift check CI runs to catch a stale pin.
func CheckPins(reg *Registry, repoRoot string) ([]StalePin, error) {
	var stale []StalePin
	targets := make([]Target, 0, len(reg.Pins))
	for t := range reg.Pins {
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })

	for _, t := range targets {
		pin := reg.Pins[t]
		if pin.InputsHash == "" {
			continue
		}
		cur, err := InputsHash(repoRoot, t)
		if err != nil {
			return nil, err
		}
		if cur == "" {
			continue
		}
		if cur != pin.InputsHash {
			stale = append(stale, StalePin{Target: t, Recorded: pin.InputsHash, Current: cur})
		}
	}
	return stale, nil
}
