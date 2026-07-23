package attest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every backend must define every control (no missing cells) with a known
// enforcement value, and backend ids must be unique.
func TestMatrix_Complete(t *testing.T) {
	known := map[Enforcement]bool{Enforced: true, FailClosed: true, NotEnforced: true, NotApplicable: true}
	seen := map[string]bool{}
	for _, be := range ConfidentialMatrix {
		assert.False(t, seen[be.ID], "duplicate backend id %q", be.ID)
		seen[be.ID] = true
		assert.NotEmpty(t, be.Short, "%s: missing column header", be.ID)
		assert.NotEmpty(t, be.Anchor, "%s: missing root of trust", be.ID)
		for _, ctrl := range controlOrder {
			e, ok := be.Controls[ctrl]
			require.Truef(t, ok, "%s: control %q is undefined", be.ID, ctrl)
			assert.Truef(t, known[e], "%s/%q: unknown enforcement %q", be.ID, ctrl, e)
		}
	}
}

// TestMatrix_DocInSync is the anti-drift lock: the security doc embeds the
// generated table verbatim, so a verifier change reflected in the matrix but not
// the doc (or vice versa) fails here. Regenerate by pasting RenderMarkdown().
func TestMatrix_DocInSync(t *testing.T) {
	doc, err := os.ReadFile("../../docs/confidential-computing.md")
	require.NoError(t, err)
	rendered := RenderMarkdown()
	if !strings.Contains(string(doc), strings.TrimRight(rendered, "\n")) {
		t.Fatalf("docs/confidential-computing.md is out of sync with internal/attest/matrix.go.\n"+
			"Replace the block between the generated-matrix markers with:\n\n%s", rendered)
	}
}

// TestMatrix_GroundedInCode ties the security-critical, backend-differentiating
// cells to the actual verifier behavior, so the matrix can't silently misdescribe
// what the code enforces.
func TestMatrix_GroundedInCode(t *testing.T) {
	// The measured SEV-SNP path (azure-snp) enforces debug-off, migration-off, and
	// the TCB floor. Ground those "enforced" cells against the LIVE verifier
	// (verifyAzureSNP), not a parallel policy impl — a full evidence bundle carrying
	// each violation must be rejected.
	snpNonce := bytes.Repeat([]byte{0x5a}, 32)
	snpCK := []byte("azure-channel-public-key-32-byte")
	snpPCR11 := make48(0xAB)[:32]
	snpPin := map[int]string{11: hex.EncodeToString(snpPCR11)}

	evDbg, roots := azureEvidencePolicy(t, snpNonce, snpCK, snpPCR11, snpPolicyDebug, 9)
	_, _, err := verifyAzureSNP(evDbg, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)), Roots: roots, Nonce: snpNonce, PCRs: snpPin})
	assert.Error(t, err, "matrix says debug-off is enforced on the SNP path")

	evMig, roots := azureEvidencePolicy(t, snpNonce, snpCK, snpPCR11, snpPolicyMigrateMA, 9)
	_, _, err = verifyAzureSNP(evMig, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)), Roots: roots, Nonce: snpNonce, PCRs: snpPin})
	assert.Error(t, err, "matrix says migration-off is enforced on the SNP path")

	evWeak, roots := azureEvidencePolicy(t, snpNonce, snpCK, snpPCR11, 0, 1)
	_, _, err = verifyAzureSNP(evWeak, AzureSNPPolicy{Measurement: hex.EncodeToString(make48(0x11)), Roots: roots, Nonce: snpNonce, PCRs: snpPin, MinTCB: 0xFF})
	assert.Error(t, err, "matrix says the TCB floor is enforced on the SNP path")

	// The GCP Confidential Space path can't read a TCB, so it fail-closes on
	// minTCB (no silent ignore) — matching the matrix.
	assert.Equal(t, FailClosed, cellFor(t, "gcp-confidential-space", ControlMinTCB))
	key, keys := jwtSigningKey(t)
	ck := bytes.Repeat([]byte{0x9A}, 32)
	tok := mintJWT(t, "maa1", "RS256", key, validCSClaims())
	csErr := CSValidator(keys, []string{csDigest}, "sev-snp", 7).Validate(context.Background(), []byte(tok), ck, csNonce)
	require.Error(t, csErr, "gcp-confidential-space minTCB must fail closed, matching the matrix")

	// Revocation is enforced on the AMD-cert-chain path (azure-snp) and is n/a on
	// the JWS paths (delegated to the cloud service) and Nitro (ephemeral certs).
	// Ground the azure-snp cell against the real check: a revoked ASK is rejected.
	assert.Equal(t, Enforced, cellFor(t, "azure-snp", ControlRevocation))
	for _, id := range []string{"gcp-confidential-space", "aws-nitro"} {
		assert.Equal(t, NotApplicable, cellFor(t, id, ControlRevocation), "%s delegates or has no cert chain to revoke", id)
	}
	snpChain := newSNPChain(t)
	installCRL(t, arkSignedCRL(t, snpChain, snpChain.ask.SerialNumber)) // ASK revoked
	assert.Error(t, azureSNPCheckRevocation(snpChain.vcek, snpChain.ask, []*x509.Certificate{snpChain.ark}),
		"a revoked ASK must be rejected, matching the azure-snp revocation cell")
}

// cellFor looks up a backend's enforcement of a control, failing the test if the
// backend id is unknown.
func cellFor(t *testing.T, backendID string, ctrl Control) Enforcement {
	t.Helper()
	for _, be := range ConfidentialMatrix {
		if be.ID == backendID {
			return be.Controls[ctrl]
		}
	}
	t.Fatalf("unknown backend %q", backendID)
	return ""
}
