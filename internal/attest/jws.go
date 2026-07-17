package attest

import (
	"crypto"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// allowedJWSAlgs is the exact set of signature algorithms our attestation tokens
// (GCP Confidential Space, Azure MAA) use. Passing it to ParseSigned means the
// token's own `alg` can never select an unexpected verification method — the
// library rejects `none`, HMAC, and everything else before any key is touched
// (the classic algorithm-confusion attack).
var allowedJWSAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// verifyJWS verifies a compact JWS against a set of trusted public keys keyed by
// `kid`, and returns the verified payload. The cryptographic envelope (parsing,
// algorithm enforcement, signature verification) is delegated to the audited
// go-jose library; dispatcher's only policy here is "the signing key must be one
// we pinned by kid" — we never trust a key carried in the token.
func verifyJWS(token string, keys map[string]crypto.PublicKey) ([]byte, error) {
	jws, err := jose.ParseSigned(token, allowedJWSAlgs)
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %w", err)
	}
	// One signature only: a multi-signature JWS has no unambiguous signer for an
	// attestation token, so refuse rather than guess which one to trust.
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("JWS must carry exactly one signature, got %d", len(jws.Signatures))
	}

	kid := jws.Signatures[0].Header.KeyID
	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("JWS signed by unknown key %q", kid)
	}

	payload, err := jws.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("JWS signature invalid: %w", err)
	}
	return payload, nil
}
