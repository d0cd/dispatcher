package cloudvm

import (
	"fmt"
	"hash/crc32"
)

// Firecracker microVMs get a host-local /30 per run: host .1 is the gateway,
// guest .2 is the VM. The subnet is derived from the run id (crc32) so create
// and teardown agree without any shared allocator state. 172.16.0.0/16 yields
// 16384 distinct /30s.
const fcNetPrefix = "172.16"

func fcSubnetIndex(runID string) int {
	return int(crc32.ChecksumIEEE([]byte(runID)) % 16384)
}

// fcNetFromIndex returns the /30 endpoints for a subnet index: the host
// (gateway) IP, the guest IP, and the dotted netmask.
func fcNetFromIndex(idx int) (hostIP, guestIP, mask string) {
	base := idx * 4 // first address of the /30
	third := (base >> 8) & 0xff
	low := base & 0xff
	hostIP = fmt.Sprintf("%s.%d.%d", fcNetPrefix, third, low+1)
	guestIP = fmt.Sprintf("%s.%d.%d", fcNetPrefix, third, low+2)
	return hostIP, guestIP, "255.255.255.252"
}

// fcCIDRFromIndex returns the /30 network address in CIDR form (e.g. for NAT).
func fcCIDRFromIndex(idx int) string {
	base := idx * 4
	third := (base >> 8) & 0xff
	low := base & 0xff
	return fmt.Sprintf("%s.%d.%d/30", fcNetPrefix, third, low)
}

// fcNet returns the hash-derived /30 endpoints for a run. The create path uses
// the persisted allocated index instead (fcNetFromIndex); this remains for
// callers/tests that only have the run id.
func fcNet(runID string) (hostIP, guestIP, mask string) {
	return fcNetFromIndex(fcSubnetIndex(runID))
}

// fcNetworkCIDR returns the hash-derived /30 in CIDR form for a run.
func fcNetworkCIDR(runID string) string {
	return fcCIDRFromIndex(fcSubnetIndex(runID))
}

// fcTapName is the host tap interface for a run. Must fit IFNAMSIZ (15 chars);
// "fc" + 8 hex = 10.
func fcTapName(runID string) string {
	return fmt.Sprintf("fc%08x", crc32.ChecksumIEEE([]byte(runID)))
}

// fcGuestMAC is a stable locally-administered unicast MAC for the guest.
func fcGuestMAC(runID string) string {
	h := crc32.ChecksumIEEE([]byte(runID))
	// 0x02 = locally administered (bit 1 set), unicast (bit 0 clear).
	return fmt.Sprintf("02:00:%02x:%02x:%02x:%02x",
		byte(h>>24), byte(h>>16), byte(h>>8), byte(h))
}

// fcBootArgsWithNet appends the kernel ip= directive so the guest configures
// eth0 at boot without an in-guest network manager. Format:
// ip=<client>:<server>:<gateway>:<netmask>:<hostname>:<device>:<autoconf>.
func fcBootArgsWithNet(base, guestIP, hostIP, mask string) string {
	if base == "" {
		base = defaultFirecrackerBootArgs
	}
	return fmt.Sprintf("%s ip=%s::%s:%s::eth0:off", base, guestIP, hostIP, mask)
}

// fcTapUpArgs is the argv sequence to create a tap, address it on its /30, and
// bring it up. Each inner slice is one `ip` invocation (without the leading
// "ip", which the caller supplies via its exec seam... included here for a
// self-describing command list).
func fcTapUpArgs(tap, hostIP string) [][]string {
	return [][]string{
		{"ip", "tuntap", "add", "dev", tap, "mode", "tap"},
		{"ip", "addr", "add", hostIP + "/30", "dev", tap},
		{"ip", "link", "set", "dev", tap, "up"},
	}
}

// fcTapDownArgs removes the tap (idempotent-ish; errors ignored by the caller).
func fcTapDownArgs(tap string) [][]string {
	return [][]string{{"ip", "link", "del", tap}}
}

// fcNATArgs returns the iptables rules to NAT guest egress out hostIface and to
// forward between the tap and hostIface. del=true returns the delete variant so
// teardown removes exactly what create added.
func fcNATArgs(networkCIDR, hostIface, tap string, del bool) [][]string {
	op := "-A"
	if del {
		op = "-D"
	}
	fwd := "-I"
	if del {
		fwd = "-D"
	}
	return [][]string{
		{"iptables", "-t", "nat", op, "POSTROUTING", "-s", networkCIDR, "-o", hostIface, "-j", "MASQUERADE"},
		{"iptables", fwd, "FORWARD", "-i", tap, "-o", hostIface, "-j", "ACCEPT"},
		{"iptables", fwd, "FORWARD", "-i", hostIface, "-o", tap, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
}
