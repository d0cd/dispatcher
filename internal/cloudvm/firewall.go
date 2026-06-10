package cloudvm

import (
	"fmt"
	"net"
	"strings"
)

// Per-run firewall support (finding S7). When VMOptions.AllowSSHFrom is a
// non-empty CIDR, supported providers attach a least-privilege firewall that
// permits inbound SSH (TCP 22) only from that range. Providers that do not yet
// implement this reject a non-empty value rather than silently ignoring it.
//
// NOTE: the per-provider create/attach/delete lifecycle below is exercised by
// argv-level unit tests but has not been smoke-tested against live cloud CLIs.

const sshPort = "22"

// validateFirewallCIDR rejects anything that is not a valid CIDR, so a bare IP
// or garbage can never be interpolated into a provider's source-range arg.
func validateFirewallCIDR(cidr string) error {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid --allow-ssh-from %q: must be a CIDR like 203.0.113.4/32: %w", cidr, err)
	}
	return nil
}

// firewallNameFromString derives a deterministic, provider-portable firewall
// name from an arbitrary handle. It is lowercased and stripped to [a-z0-9-] so
// the same string is valid as a Hetzner firewall name, a GCP firewall-rule
// name, and a GCP network tag. Determinism lets DestroyVM recompute the name
// for cleanup from whatever handle it has (Hetzner: the run id recovered from
// labels; GCP: the instance name, which is the vmID).
func firewallNameFromString(handle string) string {
	var b strings.Builder
	b.WriteString("dispatcher-fw-")
	for _, r := range strings.ToLower(handle) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// firewallName is the create-time name, keyed on the run id when present.
func firewallName(opts VMOptions) string {
	id := opts.Tags["dispatcher-run-id"]
	if id == "" {
		id = opts.Name
	}
	return firewallNameFromString(id)
}

// errFirewallUnsupported is returned by providers without per-run firewall
// support so a requested AllowSSHFrom never silently no-ops.
func errFirewallUnsupported(provider string) error {
	return fmt.Errorf("--allow-ssh-from is not yet supported for %s; restrict SSH at the account/VPC level (security group / NSG) instead", provider)
}

// hetznerFirewallCreateArgs builds `hcloud firewall create`.
func hetznerFirewallCreateArgs(name string) []string {
	return []string{"firewall", "create", "--name", name}
}

// hetznerFirewallRuleArgs builds `hcloud firewall add-rule` permitting inbound
// SSH from cidr.
func hetznerFirewallRuleArgs(name, cidr string) []string {
	return []string{
		"firewall", "add-rule", name,
		"--direction", "in",
		"--protocol", "tcp",
		"--port", sshPort,
		"--source-ips", cidr,
	}
}
