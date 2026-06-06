package cloudvm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d0cd/dispatcher/internal/adapter"
	statedir "github.com/d0cd/dispatcher/internal/state"
)

// sshWrapperArg returns the wrapper path ShellQuote'd for rsync's `-e`
// value (rsync shell-parses -e).
func sshWrapperArg(state *CloudVMState) (string, error) {
	if state.SSHWrapper == "" {
		return "", fmt.Errorf("ssh wrapper not initialized for VM %s", state.VMID)
	}
	return adapter.ShellQuote(state.SSHWrapper), nil
}

// writeSSHWrapper writes a per-run shell script that invokes ssh with the
// run's pinned identity, port, and known_hosts baked in. All substitution
// happens once with proper shell quoting; callers pass only the wrapper
// path to rsync's `-e`. Mode 0700.
func writeSSHWrapper(state *CloudVMState, runID string) (string, error) {
	keyDir, err := statedir.Subdir("keys")
	if err != nil {
		return "", fmt.Errorf("ssh wrapper: %w", err)
	}
	path := filepath.Join(keyDir, "ssh-wrapper-"+runID+".sh")

	port := state.SSHPort
	if port == 0 {
		port = 22
	}

	var b strings.Builder
	b.WriteString("#!/bin/sh\nexec ssh -o ConnectTimeout=10")
	if state.KnownHostsPath != "" {
		b.WriteString(" -o StrictHostKeyChecking=yes")
		fmt.Fprintf(&b, " -o UserKnownHostsFile=%s", adapter.ShellQuote(state.KnownHostsPath))
	} else {
		b.WriteString(" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
	}
	if state.SSHKeyPath != "" {
		fmt.Fprintf(&b, " -i %s", adapter.ShellQuote(state.SSHKeyPath))
	}
	fmt.Fprintf(&b, " -p %d", port)
	b.WriteString(` "$@"` + "\n")

	if err := os.WriteFile(path, []byte(b.String()), 0o700); err != nil {
		return "", fmt.Errorf("write ssh wrapper: %w", err)
	}
	// Re-chmod: WriteFile honors umask, which could leave the script
	// group/other-readable and leak the key path.
	if err := os.Chmod(path, 0o700); err != nil {
		return "", fmt.Errorf("chmod ssh wrapper: %w", err)
	}
	return path, nil
}
