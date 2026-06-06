package cloudvm

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// DefaultWatchdogTTL is the default self-destruct timer for cloud VMs.
const DefaultWatchdogTTL = 30 * time.Minute

// WatchdogCloudInit returns a cloud-init user-data script that installs
// a self-destruct watchdog. If the deadline is not extended, the VM shuts down.
func WatchdogCloudInit(initialTTL time.Duration) string {
	deadline := time.Now().Add(initialTTL).Unix()
	return fmt.Sprintf(`#!/bin/sh
# Dispatcher watchdog: self-destruct if deadline not extended
echo %d > /var/run/dispatcher-watchdog-deadline
mkdir -p /var/log/dispatcher

# Background watchdog loop — works on any distro (no cron dependency)
(
  while true; do
    DEADLINE=$(cat /var/run/dispatcher-watchdog-deadline 2>/dev/null || echo 0)
    NOW=$(date +%%s)
    if [ "$NOW" -gt "$DEADLINE" ]; then
      logger "dispatcher-watchdog: TTL expired, shutting down" 2>/dev/null || true
      shutdown -h now 2>/dev/null || poweroff 2>/dev/null || kill 1
    fi
    sleep 60
  done
) &
`, deadline)
}

// ExtendWatchdogViaSSH updates the deadline file on the remote VM.
func ExtendWatchdogViaSSH(ctx context.Context, state *CloudVMState, ttl time.Duration) (time.Time, error) {
	newDeadline := time.Now().Add(ttl)
	remoteCmd := fmt.Sprintf("echo %d > /var/run/dispatcher-watchdog-deadline", newDeadline.Unix())

	args := sshCmdArgs(state, remoteCmd)
	if err := exec.CommandContext(ctx, "ssh", args...).Run(); err != nil {
		return time.Time{}, fmt.Errorf("failed to extend watchdog: %w", err)
	}
	return newDeadline, nil
}

// sshCmdArgs builds SSH command arguments from CloudVMState.
func sshCmdArgs(state *CloudVMState, remoteCmd string) []string {
	var args []string
	args = append(args, "-o", "StrictHostKeyChecking=no")
	args = append(args, "-o", "UserKnownHostsFile=/dev/null")
	args = append(args, "-o", "ConnectTimeout=10")
	if state.SSHKeyPath != "" {
		args = append(args, "-i", state.SSHKeyPath)
	}
	port := state.SSHPort
	if port == 0 {
		port = 22
	}
	args = append(args, "-p", fmt.Sprintf("%d", port))
	user := state.SSHUser
	if user == "" {
		user = "root"
	}
	args = append(args, fmt.Sprintf("%s@%s", user, state.IP))
	args = append(args, remoteCmd)
	return args
}
