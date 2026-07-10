package cloudvm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

func maaSigningKey(t *testing.T) (*rsa.PrivateKey, map[string]crypto.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key, map[string]crypto.PublicKey{"maa1": &key.PublicKey}
}

func TestVerifyMAAToken_ExtractsClaims(t *testing.T) {
	key, keys := maaSigningKey(t)
	meas := hex.EncodeToString(make48(0x33))
	rd := bytesRepeat(0x44, 64)
	tok := mintJWT(t, "maa1", "RS256", key, map[string]any{
		"x-ms-attestation-type":           "sevsnpvm",
		"x-ms-compliance-status":          "azure-compliant-cvm",
		"x-ms-sevsnpvm-launchmeasurement": meas,
		"x-ms-sevsnpvm-reportdata":        hex.EncodeToString(rd),
		"x-ms-sevsnpvm-is-debuggable":     false,
	})

	claims, err := verifyMAAToken(tok, keys, "")
	require.NoError(t, err)
	assert.Equal(t, "sev-snp", claims.TEEType)
	assert.Equal(t, meas, claims.Measurement)
	assert.Equal(t, rd, claims.ReportData)
	assert.False(t, claims.DebugEnabled)
}

func TestVerifyMAAToken_RejectsBadSignature(t *testing.T) {
	key, _ := maaSigningKey(t)
	_, otherKeys := maaSigningKey(t) // a different key than the one that signed
	tok := mintJWT(t, "maa1", "RS256", key, map[string]any{
		"x-ms-attestation-type":  "sevsnpvm",
		"x-ms-compliance-status": "azure-compliant-cvm",
	})
	_, err := verifyMAAToken(tok, otherKeys, "")
	require.Error(t, err, "a token not signed by a trusted MAA key must be rejected")
}

func TestVerifyMAAToken_RejectsNonCompliant(t *testing.T) {
	key, keys := maaSigningKey(t)
	tok := mintJWT(t, "maa1", "RS256", key, map[string]any{
		"x-ms-attestation-type":  "sevsnpvm",
		"x-ms-compliance-status": "not-compliant",
	})
	_, err := verifyMAAToken(tok, keys, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compliance")
}

func TestVerifyMAAToken_RejectsUnknownTEEType(t *testing.T) {
	key, keys := maaSigningKey(t)
	tok := mintJWT(t, "maa1", "RS256", key, map[string]any{
		"x-ms-attestation-type":  "mysterytee",
		"x-ms-compliance-status": "azure-compliant-cvm",
	})
	_, err := verifyMAAToken(tok, keys, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attestation type")
}

func TestVerifyMAAToken_RejectsExpiredAndWrongIssuer(t *testing.T) {
	key, keys := maaSigningKey(t)
	base := map[string]any{
		"x-ms-attestation-type":  "sevsnpvm",
		"x-ms-compliance-status": "azure-compliant-cvm",
	}

	// Expired token.
	expired := map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}
	for k, v := range base {
		expired[k] = v
	}
	_, err := verifyMAAToken(mintJWT(t, "maa1", "RS256", key, expired), keys, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")

	// Wrong issuer, when an expected issuer is configured.
	wrongIss := map[string]any{"iss": "https://evil.attest.azure.net"}
	for k, v := range base {
		wrongIss[k] = v
	}
	_, err = verifyMAAToken(mintJWT(t, "maa1", "RS256", key, wrongIss), keys, "https://trusted.attest.azure.net")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")

	// Not yet valid (nbf in the future).
	future := map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}
	for k, v := range base {
		future[k] = v
	}
	_, err = verifyMAAToken(mintJWT(t, "maa1", "RS256", key, future), keys, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet valid")
}

func TestAzureAttester_VerifyAccepts(t *testing.T) {
	key, keys := maaSigningKey(t)
	meas := make48(0x55)
	channelKey := []byte("azure-channel-key")

	att := &azureAttester{keys: keys, isReady: true,
		fetch: func(_ context.Context, _ *VMInfo, _, _ string, nonce []byte) (maaEvidence, error) {
			tok := mintJWT(t, "maa1", "RS256", key, map[string]any{
				"x-ms-attestation-type":           "sevsnpvm",
				"x-ms-compliance-status":          "azure-compliant-cvm",
				"x-ms-sevsnpvm-launchmeasurement": hex.EncodeToString(meas),
				"x-ms-sevsnpvm-reportdata":        hex.EncodeToString(bindingHash(nonce, channelKey)),
				"x-ms-sevsnpvm-is-debuggable":     false,
			})
			return maaEvidence{token: tok, channelKey: channelKey}, nil
		}}

	req := types.ConfidentialRequirement{Required: true, Type: "sev-snp",
		Measurements: []string{hex.EncodeToString(meas)}}
	res, err := att.Verify(context.Background(), &VMInfo{ID: "vm"}, "/k", "u", req)
	require.NoError(t, err)
	assert.True(t, res.Verified)
	assert.Equal(t, "sev-snp", res.Type)
	assert.Equal(t, hex.EncodeToString(meas), res.Measurement)
}

func TestAzureAttester_VerifyRejectsReplay(t *testing.T) {
	key, keys := maaSigningKey(t)
	meas := make48(0x66)
	channelKey := []byte("k")
	stale := bytesRepeat(0xCC, 32)
	att := &azureAttester{keys: keys, isReady: true,
		fetch: func(_ context.Context, _ *VMInfo, _, _ string, _ []byte) (maaEvidence, error) {
			tok := mintJWT(t, "maa1", "RS256", key, map[string]any{
				"x-ms-attestation-type":           "sevsnpvm",
				"x-ms-compliance-status":          "azure-compliant-cvm",
				"x-ms-sevsnpvm-launchmeasurement": hex.EncodeToString(meas),
				"x-ms-sevsnpvm-reportdata":        hex.EncodeToString(bindingHash(stale, channelKey)),
			})
			return maaEvidence{token: tok, channelKey: channelKey}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev-snp",
		Measurements: []string{hex.EncodeToString(meas)}}
	res, err := att.Verify(context.Background(), &VMInfo{}, "/k", "u", req)
	require.NoError(t, err)
	assert.False(t, res.Verified)
	assert.Contains(t, res.Verdict, "REPORT_DATA")
}

func TestVerifyMAAToken_RejectsNonHexReportData(t *testing.T) {
	key, keys := maaSigningKey(t)
	tok := mintJWT(t, "maa1", "RS256", key, map[string]any{
		"x-ms-attestation-type":    "sevsnpvm",
		"x-ms-compliance-status":   "azure-compliant-cvm",
		"x-ms-sevsnpvm-reportdata": "not-hex!!",
	})
	_, err := verifyMAAToken(tok, keys, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hex")
}

func TestAzureAttester_PropagatesFetchFailure(t *testing.T) {
	_, keys := maaSigningKey(t)
	att := &azureAttester{keys: keys, isReady: true,
		fetch: func(_ context.Context, _ *VMInfo, _, _ string, _ []byte) (maaEvidence, error) {
			return maaEvidence{}, fmt.Errorf("guest unreachable")
		}}
	_, err := att.Verify(context.Background(), &VMInfo{}, "/k", "u",
		types.ConfidentialRequirement{Required: true, Type: "sev-snp"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "guest unreachable")
}

func TestAzureAttester_NoFetchWired(t *testing.T) {
	_, err := (&azureAttester{isReady: true}).Verify(context.Background(), &VMInfo{}, "/k", "u",
		types.ConfidentialRequirement{Required: true, Type: "sev-snp"})
	require.Error(t, err, "an attester with no fetch must error, not panic")
}

func TestAzureAttester_NotReadyByDefault(t *testing.T) {
	assert.False(t, (&azureAttester{}).ready())
}
