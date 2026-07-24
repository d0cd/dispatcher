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
	mu      sync.Mutex
	global  map[string][]string // user-global config (~/.config/dispatcher/config.yaml)
	project map[string][]string // per-project dispatcher.yaml (overrides global)
)

// SetGlobal registers the operator-level secret commands from the user-global
// config, applied to every command. Replaces any prior global registration.
func SetGlobal(m map[string][]string) {
	mu.Lock()
	defer mu.Unlock()
	global = m
}

// SetProject registers the per-project secret commands from dispatcher.yaml. A
// project entry overrides a global entry for the same variable. Replaces any prior
// project registration.
func SetProject(m map[string][]string) {
	mu.Lock()
	defer mu.Unlock()
	project = m
}

// Get returns the value of the named secret. Precedence: an already-set
// environment variable always wins (an explicit export or CI secret), then the
// per-project command, then the user-global command. The chosen command is run
// and its trimmed stdout is cached into the environment (so a re-read, and any
// child process, sees it). A missing command or a command failure yields "" — the
// caller fails closed as if the secret were unset; the failure is surfaced on
// stderr, not swallowed.
func Get(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	mu.Lock()
	argv := project[name]
	if len(argv) == 0 {
		argv = global[name]
	}
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
