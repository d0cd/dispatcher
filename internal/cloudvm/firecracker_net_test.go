package cloudvm

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	statedir "github.com/d0cd/dispatcher/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFCAllocSubnetIndex_ProbesPastUsedAndPersists(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	id := "run_alpha"
	hashIdx := fcSubnetIndex(id)

	// Occupy this run's hash bucket with a sibling run so allocation must probe.
	base, err := statedir.Subdir("firecracker")
	require.NoError(t, err)
	sib := filepath.Join(base, "other")
	require.NoError(t, os.MkdirAll(sib, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(sib, "subnet"), []byte(strconv.Itoa(hashIdx)), 0o600))

	dir, err := fcRunDir(id)
	require.NoError(t, err)
	got, err := fcAllocSubnetIndex(id, dir)
	require.NoError(t, err)
	assert.NotEqual(t, hashIdx, got, "must not reuse a sibling's subnet")
	// The allocation is persisted so teardown/GetVM resolve the same /30.
	assert.Equal(t, got, fcReadSubnetIndex(id))
}

func TestFCNet_DistinctPer30AndStable(t *testing.T) {
	host, guest, mask := fcNet("run_abc")
	host2, guest2, mask2 := fcNet("run_abc")
	assert.Equal(t, host, host2, "derivation is stable for the same run id")
	assert.Equal(t, guest, guest2)
	assert.Equal(t, "255.255.255.252", mask)
	assert.Equal(t, mask, mask2)

	// host and guest are the two usable addresses of the same /30: host is
	// base+1, guest is base+2 (adjacent), sharing the first three octets.
	assert.True(t, strings.HasPrefix(host, "172.16."), "host in the private range: %s", host)
	assert.True(t, strings.HasPrefix(guest, "172.16."), "guest in the private range: %s", guest)
	assert.Equal(t, host[:strings.LastIndexByte(host, '.')], guest[:strings.LastIndexByte(guest, '.')],
		"host and guest share the /30 network")
	var hOct, gOct int
	fmt.Sscanf(host[strings.LastIndexByte(host, '.')+1:], "%d", &hOct)
	fmt.Sscanf(guest[strings.LastIndexByte(guest, '.')+1:], "%d", &gOct)
	assert.Equal(t, hOct+1, gOct, "guest is host+1")
	assert.Equal(t, 1, hOct%4, "host is the first usable (.base+1) of its /30")

	// A different run lands on a different subnet.
	hostB, _, _ := fcNet("run_xyz")
	assert.NotEqual(t, host, hostB, "different runs get different subnets")
}

func TestFCTapName_FitsIfnamsizAndStable(t *testing.T) {
	tap := fcTapName("run_abc")
	assert.LessOrEqual(t, len(tap), 15, "tap name must fit IFNAMSIZ (15)")
	assert.Equal(t, tap, fcTapName("run_abc"), "stable for the same run id")
	assert.NotEqual(t, tap, fcTapName("run_xyz"))
}

func TestFCGuestMAC_LocallyAdministeredAndStable(t *testing.T) {
	mac := fcGuestMAC("run_abc")
	assert.Equal(t, mac, fcGuestMAC("run_abc"))
	// Locally-administered unicast: second-least-significant bit of first octet
	// set, least-significant (multicast) clear.
	var first int
	_, err := fmt.Sscanf(mac[:2], "%x", &first)
	assert.NoError(t, err)
	assert.Equal(t, 0x02, first&0x03, "first octet must be locally-administered unicast")
}

func TestFCBootArgsWithNet_HasKernelIPDirective(t *testing.T) {
	args := fcBootArgsWithNet(defaultFirecrackerBootArgs, "172.16.0.2", "172.16.0.1", "255.255.255.252")
	assert.Contains(t, args, defaultFirecrackerBootArgs)
	// kernel ip=<client>::<gw>:<mask>::<dev>:off
	assert.Contains(t, args, "ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off")
}

func TestFCTapUpDownArgs(t *testing.T) {
	up := fcTapUpArgs("fc123", "172.16.0.1")
	// creates the tap, addresses it on the /30, brings it up
	joined := ""
	for _, c := range up {
		joined += strings.Join(c, " ") + "\n"
	}
	assert.Contains(t, joined, "tuntap add dev fc123 mode tap")
	assert.Contains(t, joined, "addr add 172.16.0.1/30 dev fc123")
	assert.Contains(t, joined, "link set dev fc123 up")

	down := fcTapDownArgs("fc123")
	assert.Contains(t, strings.Join(down[0], " "), "link del fc123")
}

func TestFCNATArgs_MasqueradeAndForward(t *testing.T) {
	add := fcNATArgs("172.16.0.0/30", "ens4", "fc123", false)
	joined := ""
	for _, c := range add {
		joined += strings.Join(c, " ") + "\n"
	}
	assert.Contains(t, joined, "POSTROUTING")
	assert.Contains(t, joined, "MASQUERADE")
	assert.Contains(t, joined, "ens4")
	assert.Contains(t, joined, "172.16.0.0/30")

	del := fcNATArgs("172.16.0.0/30", "ens4", "fc123", true)
	djoined := ""
	for _, c := range del {
		djoined += strings.Join(c, " ") + "\n"
	}
	assert.Contains(t, djoined, "-D", "delete variant removes the rules")
}
