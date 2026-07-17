package target

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

// List() promises a deterministic order. Targets outside the predefined order
// (builtin firecracker-vm, or user-added targets) must not be emitted via
// randomized map iteration.
func TestRegistryList_DeterministicOrder(t *testing.T) {
	r := NewRegistry()
	r.LoadBuiltins()
	// Two extra targets whose ids are not in the predefined order slice; with
	// map iteration their relative order would be random between calls.
	r.Add(types.TargetConfig{ID: "zeta-vm", Kind: types.TargetKindCloudVM})
	r.Add(types.TargetConfig{ID: "alpha-vm", Kind: types.TargetKindCloudVM})

	first := idsOf(r.List())
	for i := 0; i < 20; i++ {
		require.Equal(t, first, idsOf(r.List()), "List() order must be stable across calls")
	}

	// The builtin firecracker-vm must appear (it was silently dropped from the
	// order slice) and the non-ordered tail must be sorted.
	assert.Contains(t, first, "firecracker-vm")
	assertSortedTail(t, first, []string{"alpha-vm", "zeta-vm"})
}

func idsOf(ts []types.TargetConfig) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.ID
	}
	return out
}

// assertSortedTail checks the given ids appear in the list in the given
// (sorted) relative order.
func assertSortedTail(t *testing.T, list, want []string) {
	t.Helper()
	var got []string
	for _, id := range list {
		for _, w := range want {
			if id == w {
				got = append(got, id)
			}
		}
	}
	assert.Equal(t, want, got, "non-ordered targets must be emitted in sorted order")
}
