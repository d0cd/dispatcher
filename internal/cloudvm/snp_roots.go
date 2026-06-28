package cloudvm

import (
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
)

// AMD ARK roots captured from AMD's Key Distribution Service
// (https://kdsintf.amd.com/vcek/v1/<product>/cert_chain). Stored PEM-encoded
// with a .crt extension. These are the self-signed trust anchors for SEV-SNP
// attestation; a captured VCEK→ASK chain is only trusted if its ASK chains to
// one of these.
//
//go:embed amd_roots/*.crt
var amdRootFS embed.FS

// amdRoots are the pinned AMD ARK roots, parsed once at package load. A parse
// failure is a build/packaging fault (the certs are compiled in), so it panics.
var amdRoots = mustLoadAMDRoots()

func mustLoadAMDRoots() []*x509.Certificate {
	entries, err := amdRootFS.ReadDir("amd_roots")
	if err != nil {
		panic(fmt.Sprintf("cloudvm: cannot read embedded AMD roots: %v", err))
	}
	var roots []*x509.Certificate
	for _, e := range entries {
		data, err := amdRootFS.ReadFile("amd_roots/" + e.Name())
		if err != nil {
			panic(fmt.Sprintf("cloudvm: cannot read embedded AMD root %s: %v", e.Name(), err))
		}
		block, _ := pem.Decode(data)
		if block == nil {
			panic(fmt.Sprintf("cloudvm: embedded AMD root %s is not PEM", e.Name()))
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(fmt.Sprintf("cloudvm: embedded AMD root %s does not parse: %v", e.Name(), err))
		}
		roots = append(roots, cert)
	}
	return roots
}
