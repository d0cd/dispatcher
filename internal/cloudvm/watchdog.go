package cloudvm

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// DefaultWatchdogTTL is the default self-destruct timer for cloud VMs.
const DefaultWatchdogTTL = 30 * time.Minute

// watchdogDeadlinePath is the durable deadline file. It lives under
// /var/lib (on-disk) rather than /var/run (tmpfs) so the deadline survives a
// reboot — otherwise a kernel panic / OOM reboot / provider maintenance would
// wipe it and the cost-cap backstop would silently never fire again.
const watchdogDeadlinePath = "/var/lib/dispatcher/watchdog-deadline"

// DefaultWatchdogSelfDestruct halts the OS when the deadline passes. On AWS/GCP a
// guest halt stops compute billing; on Hetzner the server bills as long as it
// exists (running or off) so the deleting backstop is `dispatcher gc`.
const DefaultWatchdogSelfDestruct = `shutdown -h now 2>/dev/null || poweroff 2>/dev/null || kill 1`

// azureWatchdogSelfDestruct deallocates the VM through its own managed identity
// before halting. A bare halt leaves an Azure VM "Stopped (allocated)" — still
// fully compute-billing; only a control-plane deallocate stops charges. The guest
// gets an IMDS token for its system-assigned identity (granted deallocate rights
// on itself at create time), reads its own subscription/RG/name from instance
// metadata, and POSTs the deallocate action to ARM. If the identity or role isn't
// available the calls no-op and it falls back to halting the OS (dispatcher gc
// then reclaims the stopped-allocated VM).
func azureWatchdogSelfDestruct() string {
	return `_az_meta() { curl -s -m 10 -H Metadata:true "http://169.254.169.254/metadata/instance/compute/$1?api-version=2021-02-01&format=text"; }
  AZ_TOKEN=$(curl -s -m 10 -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
  AZ_SUB=$(_az_meta subscriptionId); AZ_RG=$(_az_meta resourceGroupName); AZ_VM=$(_az_meta name)
  if [ -n "$AZ_TOKEN" ] && [ -n "$AZ_SUB" ] && [ -n "$AZ_RG" ] && [ -n "$AZ_VM" ]; then
    curl -s -m 30 -X POST -H "Authorization: Bearer $AZ_TOKEN" -H "Content-Length: 0" "https://management.azure.com/subscriptions/$AZ_SUB/resourceGroups/$AZ_RG/providers/Microsoft.Compute/virtualMachines/$AZ_VM/deallocate?api-version=2023-07-01" && logger "dispatcher-watchdog: deallocate requested" 2>/dev/null || true
    sleep 30
  fi
  ` + DefaultWatchdogSelfDestruct
}

// watchdogSelfDestructFor returns the deadline-expiry action for a provider.
// Azure deallocates via IMDS (a guest halt would keep billing); every other
// provider halts the OS.
func watchdogSelfDestructFor(p ProviderID) string {
	if p == ProviderAzure {
		return azureWatchdogSelfDestruct()
	}
	return DefaultWatchdogSelfDestruct
}

// WatchdogCloudInit returns a cloud-init user-data script that installs
// a self-destruct watchdog. The initial deadline is computed at VM boot
// time, not at script-generation time — slow provisioning (cloud-init
// taking minutes) previously caused the VM to boot already past the
// deadline and shut itself down before dispatcher could ever reconnect.
//
// The poll loop is installed as a systemd service (Restart=always, enabled
// for multi-user.target) rather than a bare backgrounded subshell, so it is
// re-launched after a reboot and re-reads the persisted deadline — shutting
// down immediately if the deadline already passed.
//
// selfDestruct is the shell run when the deadline passes — DefaultWatchdogSelfDestruct
// for most providers, azureWatchdogSelfDestruct for Azure (see watchdogSelfDestructFor).
func WatchdogCloudInit(initialTTL time.Duration, loginUser, selfDestruct string) string {
	ttlSeconds := int(initialTTL.Seconds())
	// cloud-init runs as root, so the deadline file it writes is root-owned.
	// Renewal (ExtendWatchdogViaSSH) connects as the login user, which is
	// non-root on most clouds (ubuntu/dispatcher/ec2-user); hand the file to
	// that user so its `echo > deadline` can write. When the login user is
	// already root the chown is a no-op and is omitted.
	chownDeadline := ""
	if loginUser != "" && loginUser != "root" {
		chownDeadline = fmt.Sprintf("chown %s %s", loginUser, watchdogDeadlinePath)
	}
	return fmt.Sprintf(`#!/bin/sh
# Dispatcher watchdog: self-destruct if deadline not extended.
# Deadline is computed at boot so provisioning delays don't pre-expire it.
mkdir -p /var/log/dispatcher /var/lib/dispatcher
echo $(($(date +%%s) + %d)) > %s
%s

cat > /usr/local/bin/dispatcher-watchdog.sh <<'WATCHDOG_EOF'
#!/bin/sh
while true; do
  DEADLINE=$(cat %s 2>/dev/null || echo 0)
  NOW=$(date +%%s)
  if [ "$NOW" -gt "$DEADLINE" ]; then
    logger "dispatcher-watchdog: TTL expired, shutting down" 2>/dev/null || true
    %s
  fi
  sleep 60
done
WATCHDOG_EOF
chmod +x /usr/local/bin/dispatcher-watchdog.sh

cat > /etc/systemd/system/dispatcher-watchdog.service <<'UNIT_EOF'
[Unit]
Description=Dispatcher self-destruct watchdog
After=network.target

[Service]
ExecStart=/usr/local/bin/dispatcher-watchdog.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT_EOF

systemctl daemon-reload
systemctl enable --now dispatcher-watchdog.service
`, ttlSeconds, watchdogDeadlinePath, chownDeadline, watchdogDeadlinePath, selfDestruct)
}

// ExtendWatchdogViaSSH updates the deadline file on the remote VM.
func ExtendWatchdogViaSSH(ctx context.Context, state *CloudVMState, ttl time.Duration) (time.Time, error) {
	newDeadline := time.Now().Add(ttl)
	remoteCmd := fmt.Sprintf("echo %d > %s", newDeadline.Unix(), watchdogDeadlinePath)

	args := sshCmdArgs(state, remoteCmd)
	if err := exec.CommandContext(ctx, "ssh", args...).Run(); err != nil {
		return time.Time{}, fmt.Errorf("failed to extend watchdog: %w", err)
	}
	return newDeadline, nil
}

// sshCmdArgs builds SSH command arguments from CloudVMState. When state has
// a populated KnownHostsPath, strict host key checking is enforced against it
// (defense against MITM on reconnects). When empty — only possible during the
// first connection before keyscan has run, or for legacy state files — we
// fall back to permissive checking with a clear log note.
func sshCmdArgs(state *CloudVMState, remoteCmd string) []string {
	var args []string
	if state.KnownHostsPath != "" {
		args = append(args, "-o", "StrictHostKeyChecking=yes")
		args = append(args, "-o", fmt.Sprintf("UserKnownHostsFile=%s", state.KnownHostsPath))
	} else {
		// First-connection or legacy state. The right call site (provisioning)
		// should immediately follow with PinHostKey to populate KnownHostsPath.
		args = append(args, "-o", "StrictHostKeyChecking=no")
		args = append(args, "-o", "UserKnownHostsFile=/dev/null")
	}
	args = append(args, "-o", "ConnectTimeout=10")
	args = append(args, "-o", "ServerAliveInterval=15")
	args = append(args, "-o", "ServerAliveCountMax=6")
	if state.SSHKeyPath != "" {
		// -i adds an identity but does not stop ssh-agent identities from being
		// offered first. A busy agent can hit sshd's MaxAuthTries before the
		// per-run key, yielding "Too many authentication failures".
		args = append(args, "-o", "IdentitiesOnly=yes")
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
