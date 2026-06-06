package cloudvm

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

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
