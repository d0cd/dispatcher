package attest

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
)

// AWS Nitro Enclaves Root-G1 — the self-signed trust anchor for Nitro attestation
// documents (COSE_Sign1 signed by the Nitro hypervisor's PKI). Pinned by embedding
// rather than fetched at runtime; its SHA-256 fingerprint is AWS's published
// 641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b, valid to 2049.
//
//go:embed nitro_roots/aws-nitro-root-g1.pem
var awsNitroRootPEM []byte

// awsNitroRoots is the pinned AWS Nitro root pool, parsed once at package load. A
// parse failure is a build/packaging fault (the cert is compiled in), so it panics.
var awsNitroRoots = mustLoadNitroRoots()

func mustLoadNitroRoots() *x509.CertPool {
	block, _ := pem.Decode(awsNitroRootPEM)
	if block == nil {
		panic("attest: embedded AWS Nitro root is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("attest: embedded AWS Nitro root does not parse: %v", err))
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
