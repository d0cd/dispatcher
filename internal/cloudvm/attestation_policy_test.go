package cloudvm

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testNonce = bytes.Repeat([]byte{0xAB}, 32)

func validClaims() Claims {
	return Claims{
		TEEType:          "sev-snp",
		Measurement:      "abc123",
		DebugEnabled:     false,
		MigrationEnabled: false,
		TCB:              10,
		ReportData:       bindingHash(testNonce, []byte("key")),
	}
}

func validPolicy() VerificationPolicy {
	return VerificationPolicy{
		ExpectedType: "sev-snp",
		Measurements: []string{"ABC123"}, // exact, case-insensitive hex
		MinTCB:       5,
		Nonce:        testNonce,
		ChannelKey:   []byte("key"),
	}
}

func TestApplyPolicy_FailsClosedOnMissingBindingInputs(t *testing.T) {
	// Empty nonce/key/report-data must be rejected — otherwise the binding
	// check degenerates to matching SHA-512(""), a public constant.
	t.Run("empty nonce", func(t *testing.T) {
		p := validPolicy()
		p.Nonce = nil
		assert.Error(t, applyPolicy(validClaims(), p))
	})
	t.Run("short nonce", func(t *testing.T) {
		p := validPolicy()
		p.Nonce = []byte("short")
		assert.Error(t, applyPolicy(validClaims(), p))
	})
	t.Run("empty channel key", func(t *testing.T) {
		p := validPolicy()
		p.ChannelKey = nil
		assert.Error(t, applyPolicy(validClaims(), p))
	})
	t.Run("empty report data", func(t *testing.T) {
		c := validClaims()
		c.ReportData = nil
		assert.Error(t, applyPolicy(c, validPolicy()))
	})
	t.Run("the SHA-512 empty constant does not pass", func(t *testing.T) {
		c := validClaims()
		c.ReportData = bindingHash(nil, nil) // = SHA-512("")
		assert.Error(t, applyPolicy(c, validPolicy()))
	})
}

func TestApplyPolicy_AcceptsValid(t *testing.T) {
	require.NoError(t, applyPolicy(validClaims(), validPolicy()))
}

func TestApplyPolicy_Rejects(t *testing.T) {
	cases := map[string]func(c *Claims){
		"debug enabled":        func(c *Claims) { c.DebugEnabled = true },
		"migration enabled":    func(c *Claims) { c.MigrationEnabled = true },
		"wrong tee type":       func(c *Claims) { c.TEEType = "tdx" },
		"tcb below minimum":    func(c *Claims) { c.TCB = 1 },
		"unlisted measurement": func(c *Claims) { c.Measurement = "deadbeef" },
		"report-data mismatch": func(c *Claims) { c.ReportData = []byte("wrong-binding") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validClaims()
			mutate(&c)
			assert.Error(t, applyPolicy(c, validPolicy()))
		})
	}
}

func TestApplyPolicy_AnyTypeAccepts(t *testing.T) {
	p := validPolicy()
	p.ExpectedType = "any"
	c := validClaims()
	c.TEEType = "tdx" // type "any" accepts whatever the TEE proves
	require.NoError(t, applyPolicy(c, p))
}

func TestApplyPolicy_EmptyAllowlistFailsClosed(t *testing.T) {
	p := validPolicy()
	p.Measurements = nil
	require.Error(t, applyPolicy(validClaims(), p), "no measurement allowlist must fail closed (R7)")
}

// REPORTED_TCB is a packed per-component SVN struct, not a monotonic integer.
// A raw u64 compare would wrongly accept a report whose bootloader SVN is below
// the minimum just because a high-order component (microcode) is set.
func TestApplyPolicy_TCBComparedPerComponent(t *testing.T) {
	c := validClaims()
	c.TCB = uint64(2) << 56 // microcode SVN 2, bootloader SVN 0 — raw u64 is huge
	p := validPolicy()
	p.MinTCB = 1 // bootloader SVN 1 (raw u64 = 1)
	assert.Error(t, applyPolicy(c, p),
		"bootloader 0 < required 1 must reject even though the raw u64 (2<<56) exceeds 1")

	// All components at/above the minimum passes.
	c.TCB = (uint64(3) << 56) | 5 // microcode 3, bootloader 5
	assert.NoError(t, applyPolicy(c, p))
}

// TestApplyPolicy_BindingIsBitExact proves the anti-replay/relay binding is an
// exact match — no single-bit change to REPORT_DATA, and no different nonce or
// channel key, can satisfy it. This guards against a truncated or partial
// comparison silently weakening the freshness/key binding.
func TestApplyPolicy_BindingIsBitExact(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xA5}, 32)
	channelKey := bytes.Repeat([]byte{0x5A}, 32)
	policy := VerificationPolicy{
		ExpectedType: "sev-snp", Measurements: []string{"abcd"},
		Nonce: nonce, ChannelKey: channelKey,
	}
	good := Claims{TEEType: "sev-snp", Measurement: "abcd", ReportData: bindingHash(nonce, channelKey)}
	require.NoError(t, applyPolicy(good, policy), "the exact binding must be accepted")

	for i := range good.ReportData {
		for bit := 0; bit < 8; bit++ {
			c := good
			rd := append([]byte(nil), good.ReportData...)
			rd[i] ^= 1 << uint(bit)
			c.ReportData = rd
			if applyPolicy(c, policy) == nil {
				t.Fatalf("a one-bit change to REPORT_DATA (byte %d, bit %d) was accepted", i, bit)
			}
		}
	}

	p2 := policy
	p2.Nonce = bytes.Repeat([]byte{0xA6}, 32)
	require.Error(t, applyPolicy(good, p2), "a different nonce must not satisfy the binding")
	p3 := policy
	p3.ChannelKey = bytes.Repeat([]byte{0x5B}, 32)
	require.Error(t, applyPolicy(good, p3), "a different channel key must not satisfy the binding")
}

func TestBindingHash_Deterministic(t *testing.T) {
	h1 := bindingHash([]byte("n"), []byte("k"))
	h2 := bindingHash([]byte("n"), []byte("k"))
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64, "SEV-SNP REPORT_DATA is 64 bytes (SHA-512)")
	assert.NotEqual(t, h1, bindingHash([]byte("n"), []byte("k2")))
}
