package attest

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// AWS Nitro Enclaves attestation is a COSE_Sign1 document whose CBOR payload the
// Nitro Security Module fills and the Nitro hypervisor signs. Unlike SEV-SNP (EC2
// measures only the guest firmware) a Nitro enclave's image IS measured: PCR0 is
// the whole enclave image, PCR1 the kernel+bootstrap, PCR2 the application. So
// pinning PCR0 attests the exact agent+workload image — this is what closes the
// agent-not-measured caveat on AWS. public_key/nonce carry the run binding.

// nitroDoc is the CBOR payload of a Nitro attestation document.
type nitroDoc struct {
	ModuleID    string          `cbor:"module_id"`
	Digest      string          `cbor:"digest"`
	Timestamp   uint64          `cbor:"timestamp"`
	PCRs        map[uint][]byte `cbor:"pcrs"`
	Certificate []byte          `cbor:"certificate"` // leaf (NSM) cert DER
	CABundle    [][]byte        `cbor:"cabundle"`    // chain DER up toward the Nitro root
	PublicKey   []byte          `cbor:"public_key"`  // verifier-bound channel key
	UserData    []byte          `cbor:"user_data"`
	Nonce       []byte          `cbor:"nonce"` // verifier-bound freshness challenge
}

// NitroPolicy is what an AWS Nitro Enclaves run demands of an attestation document:
// the per-run nonce it must echo and the pinned PCR values (index → hex) of the
// known-good enclave image (from `nitro-cli build-enclave`).
type NitroPolicy struct {
	Nonce []byte
	PCRs  map[int]string
}

// verifyNitroDoc verifies a Nitro attestation document: the certificate chain from
// the embedded leaf through the cabundle to the pinned Nitro root, the COSE_Sign1
// signature over the payload (ES384, the leaf key), the per-run nonce, and the
// pinned PCRs. On success it returns the PCR0 measurement (hex) and the bound
// channel public key (the doc's public_key) to seal to.
func verifyNitroDoc(coseBytes []byte, roots *x509.CertPool, p NitroPolicy) (measurement string, channelKey []byte, err error) {
	// The Nitro Security Module emits an untagged COSE_Sign1 (a bare 4-element
	// array, no CBOR tag 18); accept either form.
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(coseBytes); err != nil {
		var untagged cose.UntaggedSign1Message
		if uerr := untagged.UnmarshalCBOR(coseBytes); uerr != nil {
			return "", nil, fmt.Errorf("parse COSE_Sign1: %w", err)
		}
		msg = cose.Sign1Message(untagged)
	}
	var doc nitroDoc
	if err := cbor.Unmarshal(msg.Payload, &doc); err != nil {
		return "", nil, fmt.Errorf("parse attestation payload: %w", err)
	}

	// 1. Certificate chain: leaf → cabundle → the pinned AWS Nitro root.
	leaf, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return "", nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	inter := x509.NewCertPool()
	for _, der := range doc.CABundle {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", nil, fmt.Errorf("parse cabundle cert: %w", err)
		}
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return "", nil, fmt.Errorf("nitro certificate chain: %w", err)
	}

	// 2. COSE_Sign1 signature over the payload, by the leaf's key (ES384).
	verifier, err := cose.NewVerifier(cose.AlgorithmES384, leaf.PublicKey)
	if err != nil {
		return "", nil, fmt.Errorf("nitro verifier: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return "", nil, fmt.Errorf("nitro COSE signature: %w", err)
	}

	// 3. Freshness + channel-key binding: the doc must echo this run's nonce and
	// carry the channel key to seal to.
	if len(p.Nonce) == 0 {
		return "", nil, fmt.Errorf("nitro policy nonce missing — fail closed")
	}
	if !bytes.Equal(doc.Nonce, p.Nonce) {
		return "", nil, fmt.Errorf("nitro attestation nonce does not match this run's challenge (replay/relay)")
	}
	if len(doc.PublicKey) == 0 {
		return "", nil, fmt.Errorf("nitro attestation carries no public_key to bind the sealing channel")
	}

	// 4. Pinned PCRs (PCR0 = enclave image, PCR1 = kernel+bootstrap, PCR2 = app).
	if len(p.PCRs) == 0 {
		return "", nil, fmt.Errorf("nitro policy pins no PCRs — fail closed (nothing attests the enclave image)")
	}
	for idx, want := range p.PCRs {
		got, ok := doc.PCRs[uint(idx)]
		if !ok {
			return "", nil, fmt.Errorf("nitro doc does not attest pcr%d", idx)
		}
		if hex.EncodeToString(got) != want {
			return "", nil, fmt.Errorf("nitro pcr%d does not match the pinned enclave measurement", idx)
		}
	}

	return hex.EncodeToString(doc.PCRs[0]), doc.PublicKey, nil
}
