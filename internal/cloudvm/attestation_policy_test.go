package cloudvm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validClaims() Claims {
	return Claims{
		TEEType:          "sev-snp",
		Measurement:      "abc123",
		DebugEnabled:     false,
		MigrationEnabled: false,
		TCB:              10,
		ReportData:       bindingHash([]byte("nonce"), []byte("key")),
	}
}

func validPolicy() VerificationPolicy {
	return VerificationPolicy{
		ExpectedType: "sev-snp",
		Measurements: []string{"ABC123"}, // exact, case-insensitive hex
		MinTCB:       5,
		Nonce:        []byte("nonce"),
		ChannelKey:   []byte("key"),
	}
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
