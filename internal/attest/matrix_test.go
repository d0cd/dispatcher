package attest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
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
	// The raw-report paths (AWS SEV-SNP; the shared azure-snp logic mirrors it)
	// enforce debug-off, migration-off, and the TCB floor via applyPolicy. Ground
	// those "enforced" cells against the real policy engine.
	nonce := bytes.Repeat([]byte{0x5a}, 32)
	channelKey := bytes.Repeat([]byte{0x11}, 32)
	good := Claims{
		TEEType: "sev-snp", Measurement: "aa", TCB: 0xFF,
		ReportData: agent.BindingHash(nonce, channelKey),
	}
	pol := VerificationPolicy{
		ExpectedType: "sev-snp", Measurements: []string{"aa"},
		Nonce: nonce, ChannelKey: channelKey,
	}
	require.NoError(t, applyPolicy(good, pol), "a clean report must verify")

	dbg := good
	dbg.DebugEnabled = true
	assert.Error(t, applyPolicy(dbg, pol), "matrix says debug-off is enforced on the applyPolicy paths")

	mig := good
	mig.MigrationEnabled = true
	assert.Error(t, applyPolicy(mig, pol), "matrix says migration-off is enforced on the applyPolicy paths")

	weak := good
	weak.TCB = 0x01
	assert.Error(t, applyPolicy(weak, pol.withMinTCB(0xFF)), "matrix says the TCB floor is enforced on the applyPolicy paths")

	// The Azure MAA path can't read a TCB, so the matrix marks minTCB fail-closed:
	// a run that sets minTCB must be rejected (not silently ignored).
	assert.Equal(t, FailClosed, cellFor(t, "azure-maa", ControlMinTCB))
	key, keys := maaSigningKey(t)
	ck := bytes.Repeat([]byte{0x9A}, 32)
	att := &azureAttester{keys: keys, issuer: maaIssuer,
		fetch: func(_ context.Context, n []byte) (maaEvidence, error) {
			c := validMAAClaims()
			c["x-ms-runtime"].(map[string]any)["client-payload"].(map[string]any)["nonce"] =
				base64.StdEncoding.EncodeToString(agent.MAABindingNonce(n, ck))
			return maaEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: ck}, nil
		}}
	_, err := att.Verify(context.Background(), types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{maaMeasurement}, MinTCB: 7})
	require.Error(t, err, "azure-maa minTCB must fail closed, matching the matrix")

	// The GCP Confidential Space path also can't read a TCB, so it fail-closes on
	// minTCB (no silent ignore) — matching the matrix.
	assert.Equal(t, FailClosed, cellFor(t, "gcp-confidential-space", ControlMinTCB))
	cs := &csAttester{keys: keys,
		fetch: func(_ context.Context, n []byte) (csEvidence, error) {
			c := validCSClaims()
			c["eat_nonce"] = []string{hex.EncodeToString(n)}
			return csEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: ck}, nil
		}}
	_, csErr := cs.Verify(context.Background(), types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{csDigest}, MinTCB: 7})
	require.Error(t, csErr, "gcp-confidential-space minTCB must fail closed, matching the matrix")

	// Revocation is enforced on the AMD-cert-chain paths (AWS + azure-snp) and is
	// n/a on the JWS paths (delegated to the cloud service) and Nitro (ephemeral
	// certs). Ground the azure-snp cell against the real check: a revoked ASK is
	// rejected and a fetch failure fails closed.
	assert.Equal(t, Enforced, cellFor(t, "aws-sev-snp", ControlRevocation))
	assert.Equal(t, Enforced, cellFor(t, "azure-snp", ControlRevocation))
	for _, id := range []string{"gcp-confidential-space", "azure-maa", "aws-nitro"} {
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

// withMinTCB returns a copy of the policy with a raised TCB floor.
func (p VerificationPolicy) withMinTCB(min uint64) VerificationPolicy {
	p.MinTCB = min
	return p
}
