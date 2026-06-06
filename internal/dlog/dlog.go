// Package dlog provides a process-wide structured (JSON) log file alongside
// dispatch's existing human-readable stderr output. Users care about the
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
// <state-dir>/dispatch.log (append, 0600); subsequent callers reuse it.
// If the log file cannot be opened, logs are discarded silently — dispatch
// must never fail a real workload because logging broke.
func L() *slog.Logger {
	once.Do(func() {
		logger = slog.New(slog.NewJSONHandler(openLogFile(), &slog.HandlerOptions{Level: slog.LevelInfo}))
	})
	return logger
}

func openLogFile() io.Writer {
	dir, err := state.Dir()
	if err != nil {
		return io.Discard
	}
	path := filepath.Join(dir, "dispatch.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return io.Discard
	}
	return f
}
