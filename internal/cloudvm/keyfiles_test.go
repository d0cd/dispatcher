package cloudvm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	statedir "github.com/d0cd/dispatcher/internal/state"
)

func TestRemoveRunKeyFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	keyDir, err := statedir.Subdir("keys")
	require.NoError(t, err)

	mine := []string{"dispatcher-run1", "dispatcher-run1.pub", "known_hosts-run1", "ssh-wrapper-run1.sh"}
	for _, f := range append(mine, "dispatcher-other", "dispatcher-other.pub") {
		require.NoError(t, os.WriteFile(filepath.Join(keyDir, f), []byte("x"), 0o600))
	}

	RemoveRunKeyFiles("run1")

	for _, f := range mine {
		_, statErr := os.Stat(filepath.Join(keyDir, f))
		assert.True(t, os.IsNotExist(statErr), "%s should be removed", f)
	}
	_, statErr := os.Stat(filepath.Join(keyDir, "dispatcher-other"))
	assert.NoError(t, statErr, "another run's key must not be touched")
}
