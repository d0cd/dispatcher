//go:build linux

package azuresnpagent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestFirstCertDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vcek"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// A valid PEM cert returns its DER unchanged.
	got, err := firstCertDER(pemBytes)
	if err != nil {
		t.Fatalf("valid cert: %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Fatal("returned DER does not match the input certificate")
	}

	// Non-PEM input is an error, not a panic.
	if _, err := firstCertDER([]byte("not a pem block")); err == nil {
		t.Fatal("non-PEM input must error")
	}

	// A PEM block whose bytes aren't a certificate is an error.
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	if _, err := firstCertDER(bad); err == nil {
		t.Fatal("non-certificate PEM must error")
	}
}
