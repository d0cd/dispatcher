package cloudvm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// verifyJWS verifies a compact JWS (header.payload.signature, base64url) against
// a set of trusted public keys keyed by `kid`, and returns the verified payload.
//
// Only RS256 and ES256 are accepted. `none`, HMAC (`HS*`), and any other alg are
// rejected — never trust the token's alg to pick the verification method, which
// is the classic algorithm-confusion attack (e.g. an HMAC token "verified" with
// an RSA public key as the HMAC secret).
func verifyJWS(token string, keys map[string]crypto.PublicKey) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWS: want 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWS header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, fmt.Errorf("parse JWS header: %w", err)
	}

	key, ok := keys[hdr.Kid]
	if !ok {
		return nil, fmt.Errorf("JWS signed by unknown key %q", hdr.Kid)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode JWS signature: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))

	switch hdr.Alg {
	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("RS256 token but key %q is not RSA", hdr.Kid)
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], sig); err != nil {
			return nil, fmt.Errorf("RS256 signature invalid: %w", err)
		}
	case "ES256":
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ES256 token but key %q is not ECDSA", hdr.Kid)
		}
		if len(sig) != 64 {
			return nil, fmt.Errorf("ES256 signature must be 64 bytes, got %d", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ecKey, digest[:], r, s) {
			return nil, fmt.Errorf("ES256 signature invalid")
		}
	default:
		return nil, fmt.Errorf("unsupported or unsafe JWS alg %q (only RS256/ES256 allowed)", hdr.Alg)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWS payload: %w", err)
	}
	return payload, nil
}
