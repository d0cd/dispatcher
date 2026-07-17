package attest

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
	"net/url"
	"strings"
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
	// Pin the JWKS to a Google-controlled host: a tampered discovery document must
	// not be able to point us at an attacker's keys (which would become trust
	// anchors for every subsequent token).
	if err := requireGoogleHTTPSURL(cfg.JWKSURI); err != nil {
		return nil, fmt.Errorf("CS jwks_uri %q: %w", cfg.JWKSURI, err)
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
			// An empty kid would be stored at keys[""] and loosely match a token
			// with an absent kid header — reject it rather than allow that.
			if k.Kid == "" {
				return nil, fmt.Errorf("jwks RSA key has an empty kid")
			}
			nb, err := base64.RawURLEncoding.DecodeString(k.N)
			if err != nil {
				return nil, fmt.Errorf("jwks key %q modulus: %w", k.Kid, err)
			}
			eb, err := base64.RawURLEncoding.DecodeString(k.E)
			if err != nil {
				return nil, fmt.Errorf("jwks key %q exponent: %w", k.Kid, err)
			}
			pub, err := rsaPublicKeyFromJWK(nb, eb)
			if err != nil {
				return nil, fmt.Errorf("jwks key %q: %w", k.Kid, err)
			}
			keys[k.Kid] = pub
		case len(k.X5c) > 0:
			if k.Kid == "" {
				return nil, fmt.Errorf("jwks x5c key has an empty kid")
			}
			der, err := base64.StdEncoding.DecodeString(k.X5c[0])
			if err != nil {
				return nil, fmt.Errorf("jwks key %q x5c: %w", k.Kid, err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("jwks key %q cert: %w", k.Kid, err)
			}
			keys[k.Kid] = cert.PublicKey
		default:
			// Neither RSA n/e nor an x5c cert: skip other key types (e.g. EC) but
			// don't fail — as long as at least one usable key remains.
			continue
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contained no usable keys")
	}
	return keys, nil
}

// rsaPublicKeyFromJWK builds and validates an RSA public key from the raw JWK
// modulus and exponent bytes. It rejects an out-of-range exponent (which Int64
// truncation would silently corrupt) and an implausible modulus, so a malformed
// JWKS becomes an error rather than a silently wrong verification key.
func rsaPublicKeyFromJWK(nb, eb []byte) (*rsa.PublicKey, error) {
	if len(eb) == 0 || len(eb) > 4 {
		return nil, fmt.Errorf("RSA exponent has invalid length %d", len(eb))
	}
	e := int(new(big.Int).SetBytes(eb).Int64())
	if e < 3 || e%2 == 0 {
		return nil, fmt.Errorf("RSA exponent %d is not an odd value >= 3", e)
	}
	n := new(big.Int).SetBytes(nb)
	if n.Bit(0) == 0 {
		return nil, fmt.Errorf("RSA modulus is even")
	}
	if bits := n.BitLen(); bits < 2048 || bits > 16384 {
		return nil, fmt.Errorf("RSA modulus size %d bits is outside [2048, 16384]", bits)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// requireGoogleHTTPSURL returns an error unless u is an https URL whose host is
// googleapis.com or a subdomain of it.
func requireGoogleHTTPSURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("must be https")
	}
	host := parsed.Hostname()
	if host != "googleapis.com" && !strings.HasSuffix(host, ".googleapis.com") {
		return fmt.Errorf("host %q is not googleapis.com", host)
	}
	return nil
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
