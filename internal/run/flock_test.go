package run

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Concurrent Save calls must serialize behind the flock so readers never
// observe a torn JSON document (parse error) or a partially-written file.
func TestSave_ConcurrentWritesSerializeViaFlock(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("DISPATCHER_HOME", tmp)

	const writers = 12
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r := &Run{ID: "run_concurrency"}
			_, err := r.Save()
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()

	rec, err := LoadRecord("run_concurrency")
	require.NoError(t, err)
	assert.Equal(t, "run_concurrency", rec.ID)
}

func TestAtomicWriteLocked_DoesNotLeaveTmpFiles(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "thing.json")

	require.NoError(t, atomicWriteLocked(path, []byte(`{"ok":true}`), 0o600))

	entries, err := filepath.Glob(filepath.Join(tmp, "*.tmp"))
	require.NoError(t, err)
	assert.Empty(t, entries, "no .tmp files should remain after a successful write")

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, true, got["ok"])
}
