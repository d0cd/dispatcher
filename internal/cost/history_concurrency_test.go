package cost

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryStore_ConcurrentRecord_NoLost(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("DISPATCHER_HOME", tmp)

	// Simulate two dispatcher processes by constructing two separate
	// HistoryStore instances writing to the same file. Each opens
	// independently — neither sees the other's in-memory state, so a
	// load-modify-save would lose half the writes.
	const writers = 4
	const per = 50

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			s, err := NewHistoryStore()
			require.NoError(t, err)
			for i := 0; i < per; i++ {
				_ = s.Record(RunHistory{
					RunID:    fmt.Sprintf("run_w%d_i%d", wid, i),
					TargetID: "test",
					Success:  true,
				})
			}
		}(w)
	}
	wg.Wait()

	// Count lines in the file. With O_APPEND, every record produces
	// exactly one line — no overwrites, no torn lines (single Write
	// per record is <PIPE_BUF so the kernel guarantees atomicity).
	path := filepath.Join(tmp, "history.jsonl")
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)
	lines := 0
	seen := make(map[string]bool, writers*per)
	for scanner.Scan() {
		var rec RunHistory
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &rec))
		assert.False(t, seen[rec.RunID], "run id %s appeared twice — write was not atomic", rec.RunID)
		seen[rec.RunID] = true
		lines++
	}
	require.NoError(t, scanner.Err())
	assert.Equal(t, writers*per, lines,
		"expected %d entries, got %d — concurrent writers lost writes",
		writers*per, lines)
}
