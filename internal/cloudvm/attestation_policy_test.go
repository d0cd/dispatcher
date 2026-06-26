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

func TestBindingHash_Deterministic(t *testing.T) {
	h1 := bindingHash([]byte("n"), []byte("k"))
	h2 := bindingHash([]byte("n"), []byte("k"))
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64, "SEV-SNP REPORT_DATA is 64 bytes (SHA-512)")
	assert.NotEqual(t, h1, bindingHash([]byte("n"), []byte("k2")))
}
