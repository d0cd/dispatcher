package cloudvm

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGolden_MAAToken verifies dispatcher's MAA verifier against a REAL token
// captured from a live Azure SEV-SNP CVM (via the edgelesssys go-azguestattestation
// library). It confirms our claim schema matches production: the pinned issuer,
// the nested x-ms-isolation-tee SEV-SNP facts, and the client-payload nonce
// binding. Fixtures are git-ignored, so the test skips without them; the token
// expires ~8h after capture.
func TestGolden_MAAToken(t *testing.T) {
	dir := filepath.Join(fixturesDir(), "maa")
	token := strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "token.jwt"))))
	jwks := skipUnlessFixture(t, filepath.Join(dir, "jwks.json"))
	nonceHex := strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "nonce.hex"))))
	measurement := strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "measurement.txt"))))
	issuer := strings.TrimSpace(string(skipUnlessFixture(t, filepath.Join(dir, "issuer.txt"))))

	// The capture tool passed this raw nonce as the client payload; production
	// passes maaBindingNonce(runNonce, channelKey), but the verifier checks the
	// echoed value against whatever we expect, so the golden nonce is the raw one.
	nonce, err := hex.DecodeString(nonceHex)
	require.NoError(t, err)

	keys, err := parseJWKS(jwks)
	require.NoError(t, err, "the real MAA /certs JWKS must parse (x5c form)")

	got, err := verifyMAAToken(token, keys, MAAPolicy{
		Issuer: issuer, Nonce: nonce, Measurements: []string{measurement},
	})
	require.NoError(t, err, "a real MAA token must verify (confirms signature + nested schema + nonce binding)")
	assert.Equal(t, measurement, got)
}
