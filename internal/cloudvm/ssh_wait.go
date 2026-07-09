package cloudvm

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"time"
)

// sshAuthPollInterval is the retry cadence for WaitForSSHAuth (a var so tests
// can shrink it).
var sshAuthPollInterval = 5 * time.Second

// sshProbe runs a no-op authenticated SSH to confirm the key is accepted. A
// seam so the readiness retry is testable without a live host.
var sshProbe = func(ctx context.Context, state *CloudVMState) error {
	return exec.CommandContext(ctx, "ssh", sshCmdArgs(state, "true")...).Run()
}

// WaitForSSHAuth blocks until an *authenticated* SSH connection succeeds, or
// timeout. TCP-readiness (WaitForSSH) is not enough on clouds that install the
// key via boot user-data (AWS): sshd can accept connections before the key
// lands in authorized_keys, so rsync would fail with a publickey error. This
// waits for the key to actually be accepted. Requires the host key to be pinned
// first so strict host-key checking passes.
func WaitForSSHAuth(ctx context.Context, state *CloudVMState, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(sshAuthPollInterval)
	defer ticker.Stop()
	for {
		if err := sshProbe(ctx, state); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for authenticated SSH to %s after %s", state.IP, timeout)
		case <-ticker.C:
		}
	}
}

// WaitForSSH polls until the given IP is reachable on port 22,
// then waits briefly for cloud-init to finish.
func WaitForSSH(ctx context.Context, ip string, timeout time.Duration) error {
	return WaitForSSHOnPort(ctx, ip, 22, timeout)
}

// WaitForSSHOnPort is like WaitForSSH but accepts an explicit port. Lima
// forwards SSH to 127.0.0.1:<random> rather than exposing the VM's IP
// directly, so the standard "ip:22" probe never succeeds for it.
func WaitForSSHOnPort(ctx context.Context, host string, port int, timeout time.Duration) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	deadline := time.After(timeout)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for SSH on %s after %s", addr, timeout)
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err == nil {
				conn.Close()
				time.Sleep(10 * time.Second)
				return nil
			}
		}
	}
}
