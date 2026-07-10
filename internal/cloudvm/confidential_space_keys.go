package cloudvm

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// LoadGoogleCSKeys fetches the Confidential Space attestation signing keys from
// Google's OpenID configuration and parses them into a kid->key map for the JWS
// verifier. Fail-closed: an empty or unfetchable key set is an error, never a
// silently empty trust anchor.
func LoadGoogleCSKeys(ctx context.Context) (map[string]crypto.PublicKey, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	cfgBody, err := httpGetBody(ctx, client, csIssuer+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("fetch CS openid-configuration: %w", err)
	}
	var cfg struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(cfgBody, &cfg); err != nil || cfg.JWKSURI == "" {
		return nil, fmt.Errorf("CS openid-configuration has no jwks_uri: %w", err)
	}

	jwksBody, err := httpGetBody(ctx, client, cfg.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("fetch CS JWKS: %w", err)
	}
	return parseRSAJWKS(jwksBody)
}

// parseRSAJWKS parses a JWK Set of RSA keys (kid/n/e — the form Google's CS JWKS
// uses) into a kid->public-key map.
func parseRSAJWKS(raw []byte) (map[string]crypto.PublicKey, error) {
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.N == "" || k.E == "" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwks key %q modulus: %w", k.Kid, err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwks key %q exponent: %w", k.Kid, err)
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(new(big.Int).SetBytes(eb).Int64()),
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contained no usable RSA keys")
	}
	return keys, nil
}

func httpGetBody(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %d", url, resp.StatusCode)
	}
	return body, nil
}
