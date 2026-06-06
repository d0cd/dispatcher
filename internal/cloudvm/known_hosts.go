package cloudvm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	statedir "github.com/d0cd/dispatcher/internal/state"
)

// PinHostKey runs ssh-keyscan against the VM and stores the result in a
// per-run known_hosts file. Subsequent SSH calls reference this file with
// StrictHostKeyChecking=yes so an attacker can't impersonate the VM on
// reconnects.
//
// This is best-effort: if ssh-keyscan fails (network glitch, host unreachable),
// the function returns the error and the caller decides whether to abort or
// continue with permissive checking. The window for MITM is narrowed to a
// single first-connection moment regardless.
//
// state.KnownHostsPath is set on success.
func PinHostKey(ctx context.Context, state *CloudVMState, runID string) error {
	if state.IP == "" {
		return fmt.Errorf("PinHostKey: state has no IP")
	}

	keyDir, err := statedir.Subdir("keys")
	if err != nil {
		return fmt.Errorf("PinHostKey: %w", err)
	}
	knownHostsPath := filepath.Join(keyDir, "known_hosts-"+runID)

	port := state.SSHPort
	if port == 0 {
		port = 22
	}

	cmd := exec.CommandContext(ctx, "ssh-keyscan",
		"-T", "10", // 10s timeout per host
		"-p", fmt.Sprintf("%d", port),
		"-t", "ed25519,rsa", // accept both modern and legacy host keys
		state.IP,
	)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("ssh-keyscan %s: %w", state.IP, err)
	}
	if len(out) == 0 {
		return fmt.Errorf("ssh-keyscan returned no host keys for %s", state.IP)
	}

	// O_EXCL means a pre-existing file (or symlink) at the target path fails
	// the create instead of being followed or overwritten. The keys/ dir is
	// 0700 so an attacker who could plant a symlink already has full
	// same-uid access — this is defense in depth, not the primary boundary.
	f, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		// If a leftover from a previous run with the same runID exists
		// (we minted the same id again?), remove and retry. Real run IDs
		// are random so this almost always indicates we're cleaning up
		// our own crashed predecessor.
		if os.IsExist(err) {
			_ = os.Remove(knownHostsPath)
			f, err = os.OpenFile(knownHostsPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		}
		if err != nil {
			return fmt.Errorf("create known_hosts: %w", err)
		}
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		_ = os.Remove(knownHostsPath)
		return fmt.Errorf("write known_hosts: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(knownHostsPath)
		return fmt.Errorf("close known_hosts: %w", err)
	}
	state.KnownHostsPath = knownHostsPath
	return nil
}
