// Package secrets resolves named secrets (API keys, tokens) from operator-supplied
// commands, so a credential need never be written in plaintext config. A secret is
// an environment-variable name mapped to a command argv; when the variable is
// unset, the command is run and its stdout (trimmed) becomes the value. The
// mechanism is deliberately generic — dispatcher knows nothing about any specific
// secret manager; the operator supplies whatever command reads their secret.
package secrets

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// resolveTimeout bounds a single secret command. Generous, because the command
// may prompt for interactive unlock (biometrics, a passphrase) the first time.
const resolveTimeout = 2 * time.Minute

var (
	mu       sync.Mutex
	commands map[string][]string
)

// SetCommands registers the env-var → command argv map from the loaded config.
// Called once at config load, before any provider reads a secret. Replaces any
// prior registration.
func SetCommands(m map[string][]string) {
	mu.Lock()
	defer mu.Unlock()
	commands = m
}

// Get returns the value of the named secret. An already-set environment variable
// always wins (so an explicit export or CI secret overrides the command). Failing
// that, the configured command is run and its trimmed stdout is returned and
// cached into the environment (so a re-read, and any child process, sees it). A
// missing command or a command failure yields "" — the caller fails closed as if
// the secret were simply unset; the failure is surfaced on stderr, not swallowed.
func Get(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	mu.Lock()
	argv := commands[name]
	mu.Unlock()
	if len(argv) == 0 {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	if err != nil {
		// Surface the failure without leaking the command's stderr (which a secret
		// tool may echo the secret into on some error paths).
		os.Stderr.WriteString("dispatcher: secret command for " + name + " failed: " + err.Error() + "\n")
		return ""
	}
	v := strings.TrimSpace(string(out))
	if v != "" {
		_ = os.Setenv(name, v) // cache: single execution, inherited by child processes
	}
	return v
}
