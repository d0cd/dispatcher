// Package dlog provides a process-wide structured (JSON) log file alongside
// dispatcher's existing human-readable stderr output. Users care about the
// stderr; operators debugging a stuck run read the JSON file.
package dlog

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/d0cd/dispatcher/internal/state"
)

var (
	once   sync.Once
	logger *slog.Logger
)

// L returns the process-wide structured logger. The first call opens
// <state-dir>/dispatcher.log (append, 0600); subsequent callers reuse it.
// If the log file cannot be opened, logs are discarded silently — dispatcher
// must never fail a real workload because logging broke.
func L() *slog.Logger {
	once.Do(func() {
		logger = slog.New(slog.NewJSONHandler(openLogFile(), &slog.HandlerOptions{Level: slog.LevelInfo}))
	})
	return logger
}

// maxLogBytes is the rotation threshold for dispatcher.log. When the file
// exceeds this size at startup, it's renamed to dispatcher.log.1 (overwriting
// any prior rotation) and a fresh file is opened. One generation of history
// is enough for post-incident debugging without unbounded disk growth.
const maxLogBytes = 10 * 1024 * 1024 // 10 MiB

func openLogFile() io.Writer {
	dir, err := state.Dir()
	if err != nil {
		return io.Discard
	}
	path := filepath.Join(dir, "dispatcher.log")

	// Rotate on startup if the existing file is over threshold. Doing this
	// at-open rather than on-write avoids the cost (and lock dance) of
	// checking size per-log-call. Operators get at-most-2 files: the live
	// log and one rotated backup.
	if info, err := os.Stat(path); err == nil && info.Size() > maxLogBytes {
		_ = os.Rename(path, path+".1")
		// os.Rename preserves the source's mode bits. If an operator
		// previously chmod'd the live file to 0o644 to grep it, the
		// rotated backup would inherit that mode and leak past logs to
		// other users. Re-tighten to 0o600.
		_ = os.Chmod(path+".1", 0o600)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return io.Discard
	}
	// O_APPEND on a pre-existing file preserves its mode. Force 0o600 in
	// case the file was created with a different mode by a previous
	// dispatcher version or by hand.
	_ = os.Chmod(path, 0o600)
	return f
}
