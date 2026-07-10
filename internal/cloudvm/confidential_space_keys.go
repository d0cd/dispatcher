package cloudvm

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
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
	return parseJWKS(jwksBody)
}

// LoadAzureMAAKeys fetches an Azure MAA instance's signing keys from its /certs
// endpoint (a JWKS), pinning the instance by URL — we never follow the token's
// own `jku` header. Fail-closed on an empty/unfetchable key set.
func LoadAzureMAAKeys(ctx context.Context, maaURL string) (map[string]crypto.PublicKey, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	body, err := httpGetBody(ctx, client, maaURL+"/certs")
	if err != nil {
		return nil, fmt.Errorf("fetch MAA /certs: %w", err)
	}
	return parseJWKS(body)
}

// parseJWKS parses a JWK Set into a kid->public-key map, accepting both the
// `n`/`e` RSA form (Google Confidential Space) and the `x5c` certificate form
// (Azure MAA). Fail-closed: no usable keys is an error.
func parseJWKS(raw []byte) (map[string]crypto.PublicKey, error) {
	var doc struct {
		Keys []struct {
			Kid string   `json:"kid"`
			N   string   `json:"n"`
			E   string   `json:"e"`
			X5c []string `json:"x5c"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		switch {
		case k.N != "" && k.E != "":
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
		case len(k.X5c) > 0:
			der, err := base64.StdEncoding.DecodeString(k.X5c[0])
			if err != nil {
				return nil, fmt.Errorf("jwks key %q x5c: %w", k.Kid, err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("jwks key %q cert: %w", k.Kid, err)
			}
			keys[k.Kid] = cert.PublicKey
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contained no usable keys")
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
