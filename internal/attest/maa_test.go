package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
)

func maaSigningKey(t *testing.T) (*rsa.PrivateKey, map[string]crypto.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key, map[string]crypto.PublicKey{"maa1": &key.PublicKey}
}

const (
	maaIssuer      = "https://sharedeus.eus.attest.azure.net"
	maaMeasurement = "5b0ce64ad1c1f6375dbda5f760b98526"
)

var maaNonce = bytes.Repeat([]byte{0xC3}, 32)

// Baseline per-component SVNs carried by validMAAClaims, and the packed reported
// TCB they reconstruct to. Chosen non-trivial so a minTCB with any component one
// higher must be rejected.
const (
	maaBootloaderSVN = 4
	maaTEESVN        = 2
	maaSNPFwSVN      = 20
	maaMicrocodeSVN  = 115
)

// packTCB lays out per-component SVNs exactly as the SEV-SNP REPORTED_TCB u64
// does (and as tcbComponentsGTE reads): bootloader@0, TEE@8, SNP@48, microcode@56.
func packTCB(bootloader, tee, snp, microcode uint8) uint64 {
	return uint64(bootloader) | uint64(tee)<<8 | uint64(snp)<<48 | uint64(microcode)<<56
}

// validMAAClaims builds a token in the real MAA CVM shape: SEV-SNP facts nested
// under x-ms-isolation-tee, the binding nonce echoed in the top-level
// x-ms-runtime.client-payload (base64).
func validMAAClaims() map[string]any {
	return map[string]any{
		"iss":                   maaIssuer,
		"exp":                   time.Now().Add(time.Hour).Unix(),
		"nbf":                   time.Now().Add(-time.Minute).Unix(),
		"x-ms-attestation-type": "azurevm",
		"x-ms-runtime": map[string]any{
			"client-payload": map[string]any{
				"nonce": base64.StdEncoding.EncodeToString(maaNonce),
			},
		},
		"x-ms-isolation-tee": map[string]any{
			"x-ms-attestation-type":           "sevsnpvm",
			"x-ms-compliance-status":          "azure-compliant-cvm",
			"x-ms-sevsnpvm-is-debuggable":     false,
			"x-ms-sevsnpvm-launchmeasurement": maaMeasurement,
			"x-ms-sevsnpvm-bootloader-svn":    maaBootloaderSVN,
			"x-ms-sevsnpvm-tee-svn":           maaTEESVN,
			"x-ms-sevsnpvm-snpfw-svn":         maaSNPFwSVN,
			"x-ms-sevsnpvm-microcode-svn":     maaMicrocodeSVN,
		},
	}
}

func maaPolicy() MAAPolicy {
	return MAAPolicy{Issuer: maaIssuer, Nonce: maaNonce, Measurements: []string{maaMeasurement}}
}

// pcr4Good stands in for the boot-application (UKI) measurement that anchors the
// in-TEE agent on a custom measured CVM image; pcr7Good is the secure-boot state.
const (
	pcr4Good = "hCdbL0MSzU/Gy+axUq08NoPlE9nx4jw0/KFgyMynpqc="
	pcr7Good = "UaUuxQtNYIelndWuaShO9pstZqPUJUGrGROSE8JiEbQ="
)

// TestVerifyMAAToken_EnforcesPinnedPCRs is the measured-boot gate for Azure: the
// pinned PCRs (esp. PCR4, the UKI carrying the agent) attested in
// x-ms-azurevm-attested-pcr-values must match, and secure boot must be on. This
// is what closes the agent-not-measured caveat once a measured image is pinned.
func TestVerifyMAAToken_EnforcesPinnedPCRs(t *testing.T) {
	key, keys := maaSigningKey(t)
	withPCRs := func(sb bool) map[string]any {
		c := validMAAClaims()
		c["secureboot"] = sb
		c["x-ms-azurevm-attested-pcr-values"] = map[string]any{"pcr4": pcr4Good, "pcr7": pcr7Good}
		return c
	}

	// Pinned PCR4 matches the attested value + secure boot on → accepted.
	p := maaPolicy()
	p.PCRs = map[int]string{4: pcr4Good, 7: pcr7Good}
	p.RequireSecureBoot = true
	_, err := verifyMAAToken(mintJWT(t, "maa1", "RS256", key, withPCRs(true)), keys, p)
	require.NoError(t, err, "a token whose attested PCRs match the pin must verify")

	// A different pinned PCR4 (a tampered/other agent image) → rejected.
	bad := maaPolicy()
	bad.PCRs = map[int]string{4: "d3JvbmctcGNyLXZhbHVlLWZvci10ZXN0aW5nMDAwMDA9"}
	_, err = verifyMAAToken(mintJWT(t, "maa1", "RS256", key, withPCRs(true)), keys, bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pcr4", "a PCR4 mismatch must name the failing PCR")

	// Secure boot required but the token reports it off → rejected.
	sbOff := maaPolicy()
	sbOff.PCRs = map[int]string{4: pcr4Good}
	sbOff.RequireSecureBoot = true
	_, err = verifyMAAToken(mintJWT(t, "maa1", "RS256", key, withPCRs(false)), keys, sbOff)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secure boot")

	// A pinned PCR the token doesn't attest at all → rejected (fail closed).
	missing := maaPolicy()
	missing.PCRs = map[int]string{11: pcr4Good}
	_, err = verifyMAAToken(mintJWT(t, "maa1", "RS256", key, withPCRs(true)), keys, missing)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pcr11")
}

func TestVerifyMAAToken_Accepts(t *testing.T) {
	key, keys := maaSigningKey(t)
	m, err := verifyMAAToken(mintJWT(t, "maa1", "RS256", key, validMAAClaims()), keys, maaPolicy())
	require.NoError(t, err)
	assert.Equal(t, maaMeasurement, m, "returns the attested launch measurement")
}

func TestVerifyMAAToken_RejectsBadSignature(t *testing.T) {
	key, _ := maaSigningKey(t)
	_, otherKeys := maaSigningKey(t)
	_, err := verifyMAAToken(mintJWT(t, "maa1", "RS256", key, validMAAClaims()), otherKeys, maaPolicy())
	require.Error(t, err, "a token not signed by a pinned MAA key must be rejected")
}

func TestVerifyMAAToken_Rejects(t *testing.T) {
	setTEE := func(c map[string]any, k string, v any) {
		c["x-ms-isolation-tee"].(map[string]any)[k] = v
	}
	cases := map[string]struct {
		mutate func(c map[string]any)
		policy func(p *MAAPolicy)
		want   string
	}{
		"wrong issuer":        {mutate: func(c map[string]any) { c["iss"] = "https://evil.attest.azure.net" }, want: "issuer"},
		"expired":             {mutate: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, want: "expired"},
		"missing exp":         {mutate: func(c map[string]any) { delete(c, "exp") }, want: "exp"},
		"not yet valid (nbf)": {mutate: func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, want: "not yet valid"},
		"nonce not bound": {mutate: func(c map[string]any) {
			c["x-ms-runtime"].(map[string]any)["client-payload"].(map[string]any)["nonce"] = base64.StdEncoding.EncodeToString([]byte("wrong"))
		}, want: "nonce"},
		"not sevsnpvm":            {mutate: func(c map[string]any) { setTEE(c, "x-ms-attestation-type", "tdxvm") }, want: "sevsnpvm"},
		"not compliant":           {mutate: func(c map[string]any) { setTEE(c, "x-ms-compliance-status", "non-compliant") }, want: "compliant"},
		"debuggable":              {mutate: func(c map[string]any) { setTEE(c, "x-ms-sevsnpvm-is-debuggable", true) }, want: "debug"},
		"migration allowed":       {mutate: func(c map[string]any) { setTEE(c, "x-ms-sevsnpvm-migration-allowed", true) }, want: "migration"},
		"measurement not allowed": {policy: func(p *MAAPolicy) { p.Measurements = []string{"other"} }, want: "allowlist"},
		"empty allowlist":         {policy: func(p *MAAPolicy) { p.Measurements = nil }, want: "allowlist"},
		"no issuer pinned":        {policy: func(p *MAAPolicy) { p.Issuer = "" }, want: "issuer must be set"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			key, keys := maaSigningKey(t)
			c := validMAAClaims()
			if tc.mutate != nil {
				tc.mutate(c)
			}
			p := maaPolicy()
			if tc.policy != nil {
				tc.policy(&p)
			}
			_, err := verifyMAAToken(mintJWT(t, "maa1", "RS256", key, c), keys, p)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestMAABindingNonce_BindsBothInputs(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x01}, 32)
	key := bytes.Repeat([]byte{0x02}, 32)
	base := agent.MAABindingNonce(nonce, key)
	assert.Len(t, base, 32, "SHA-256 output fits the TPM quote qualifying data")
	assert.NotEqual(t, base, agent.MAABindingNonce(bytes.Repeat([]byte{0x03}, 32), key), "a different nonce changes the binding")
	assert.NotEqual(t, base, agent.MAABindingNonce(nonce, bytes.Repeat([]byte{0x04}, 32)), "a different channel key changes the binding")
	// Concatenation is order-sensitive (no ambiguity between nonce and key).
	sum := sha256.Sum256(append(append([]byte{}, nonce...), key...))
	assert.Equal(t, sum[:], base)
}

func TestAzureAttester_BindsNonceAndChannelKey(t *testing.T) {
	key, keys := maaSigningKey(t)
	channelKey := bytes.Repeat([]byte{0x9A}, 32)
	att := &azureAttester{keys: keys, issuer: maaIssuer,
		fetch: func(_ context.Context, nonce []byte) (maaEvidence, error) {
			c := validMAAClaims()
			// echo the binding the guest would have supplied
			c["x-ms-runtime"].(map[string]any)["client-payload"].(map[string]any)["nonce"] =
				base64.StdEncoding.EncodeToString(agent.MAABindingNonce(nonce, channelKey))
			return maaEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: channelKey}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{maaMeasurement}}

	res, err := att.Verify(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, res.Verified)
	assert.Equal(t, maaMeasurement, res.Measurement)
	assert.Equal(t, channelKey, res.ChannelKey, "the verified channel key is carried for sealing")
}

func TestAzureAttester_RejectsUnboundToken(t *testing.T) {
	key, keys := maaSigningKey(t)
	att := &azureAttester{keys: keys, issuer: maaIssuer,
		fetch: func(_ context.Context, _ []byte) (maaEvidence, error) {
			c := validMAAClaims() // client-payload nonce is a stale constant, not this run's binding
			return maaEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: bytes.Repeat([]byte{0x9A}, 32)}, nil
		}}
	req := types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{maaMeasurement}}

	res, err := att.Verify(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, res.Verified, "a token not binding this run's nonce+key is rejected")
	assert.Contains(t, res.Verdict, "nonce")
}

// The MAA token carries the per-component SEV-SNP SVNs, so the MAA path enforces
// a minTCB floor by reconstructing the reported TCB from them: a run whose floor
// every component meets is accepted; a floor with any component above the token's
// SVNs is a verdict (rejected), not ignored.
func TestVerifyMAAToken_EnforcesMinTCB(t *testing.T) {
	key, keys := maaSigningKey(t)

	// A floor at exactly the token's SVNs → accepted.
	atFloor := maaPolicy()
	atFloor.MinTCB = packTCB(maaBootloaderSVN, maaTEESVN, maaSNPFwSVN, maaMicrocodeSVN)
	_, err := verifyMAAToken(mintJWT(t, "maa1", "RS256", key, validMAAClaims()), keys, atFloor)
	require.NoError(t, err, "a token meeting every component floor must verify")

	// A floor one microcode SVN above the token → rejected.
	tooHigh := maaPolicy()
	tooHigh.MinTCB = packTCB(maaBootloaderSVN, maaTEESVN, maaSNPFwSVN, maaMicrocodeSVN+1)
	_, err = verifyMAAToken(mintJWT(t, "maa1", "RS256", key, validMAAClaims()), keys, tooHigh)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TCB", "a below-floor component must name TCB")

	// A token missing the SVN claims can't prove its TCB, so any positive floor
	// fails closed.
	noSVNs := validMAAClaims()
	tee := noSVNs["x-ms-isolation-tee"].(map[string]any)
	for _, k := range []string{"x-ms-sevsnpvm-bootloader-svn", "x-ms-sevsnpvm-tee-svn", "x-ms-sevsnpvm-snpfw-svn", "x-ms-sevsnpvm-microcode-svn"} {
		delete(tee, k)
	}
	floor := maaPolicy()
	floor.MinTCB = packTCB(1, 0, 0, 0)
	_, err = verifyMAAToken(mintJWT(t, "maa1", "RS256", key, noSVNs), keys, floor)
	require.Error(t, err, "a token without SVN claims must fail a positive minTCB closed")
}

// End-to-end through the attester: minTCB is now enforced on the MAA path (no
// longer a blanket fail-closed) — met floors verify, unmet floors are rejected.
func TestAzureAttester_EnforcesMinTCB(t *testing.T) {
	key, keys := maaSigningKey(t)
	channelKey := bytes.Repeat([]byte{0x9A}, 32)
	attWith := func() *azureAttester {
		return &azureAttester{keys: keys, issuer: maaIssuer,
			fetch: func(_ context.Context, nonce []byte) (maaEvidence, error) {
				c := validMAAClaims()
				c["x-ms-runtime"].(map[string]any)["client-payload"].(map[string]any)["nonce"] =
					base64.StdEncoding.EncodeToString(agent.MAABindingNonce(nonce, channelKey))
				return maaEvidence{token: mintJWT(t, "maa1", "RS256", key, c), channelKey: channelKey}, nil
			}}
	}
	base := types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{maaMeasurement}}

	met := base
	met.MinTCB = packTCB(maaBootloaderSVN, maaTEESVN, maaSNPFwSVN, maaMicrocodeSVN)
	res, err := attWith().Verify(context.Background(), met)
	require.NoError(t, err)
	assert.True(t, res.Verified, "a met minTCB floor verifies on the MAA path")

	unmet := base
	unmet.MinTCB = packTCB(maaBootloaderSVN, maaTEESVN, maaSNPFwSVN+1, maaMicrocodeSVN)
	res, err = attWith().Verify(context.Background(), unmet)
	require.NoError(t, err)
	assert.False(t, res.Verified, "an unmet minTCB floor is rejected, not ignored")
	assert.Contains(t, res.Verdict, "TCB")
}

func TestAzureAttester_NotReadyAndNoFetch(t *testing.T) {
	_, err := (&azureAttester{}).Verify(context.Background(),
		types.ConfidentialRequirement{Required: true, Type: "sev-snp"})
	require.Error(t, err, "no fetch wired must error, not panic")
}

func TestAzureAttester_PropagatesFetchFailure(t *testing.T) {
	_, keys := maaSigningKey(t)
	att := &azureAttester{keys: keys, issuer: maaIssuer,
		fetch: func(_ context.Context, _ []byte) (maaEvidence, error) {
			return maaEvidence{}, assertErr("vTPM unavailable")
		}}
	_, err := att.Verify(context.Background(),
		types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{maaMeasurement}})
	require.Error(t, err, "a fetch failure is an error, not an unverified verdict")
}
