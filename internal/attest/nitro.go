package attest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/types"
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
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(coseBytes); err != nil {
		return "", nil, fmt.Errorf("parse COSE_Sign1: %w", err)
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

// nitroFetch obtains a raw COSE_Sign1 attestation document from a booted Nitro
// enclave, binding the verifier's per-run nonce. It needs a live enclave, so it is
// the one part not unit-testable offline.
type nitroFetch func(ctx context.Context, nonce []byte) ([]byte, error)

// nitroAttester verifies AWS Nitro Enclaves attestation documents. roots is the
// pinned AWS Nitro Enclaves root; pcrs pins the known-good enclave image PCRs.
type nitroAttester struct {
	roots *x509.CertPool
	pcrs  map[int]string
	fetch nitroFetch
}

// NewAWSNitroAttester verifies AWS Nitro Enclaves attestation documents from the
// in-enclave agent endpoint, chaining to the pinned Nitro root and pinning the
// known-good enclave PCRs (PCR0 = the enclave image carrying the agent).
func NewAWSNitroAttester(roots *x509.CertPool, pcrs map[int]string, baseURL string) Attester {
	return &nitroAttester{roots: roots, pcrs: pcrs, fetch: endpointNitroFetch(baseURL)}
}

func (a *nitroAttester) Verify(ctx context.Context, _ types.ConfidentialRequirement) (AttestationResult, error) {
	if a.fetch == nil {
		return AttestationResult{}, fmt.Errorf("nitro attester has no evidence fetch wired")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return AttestationResult{}, fmt.Errorf("generate attestation nonce: %w", err)
	}
	coseBytes, err := a.fetch(ctx, nonce)
	if err != nil {
		return AttestationResult{}, fmt.Errorf("fetch nitro attestation: %w", err)
	}
	measurement, channelKey, err := verifyNitroDoc(coseBytes, a.roots, NitroPolicy{Nonce: nonce, PCRs: a.pcrs})
	if err != nil {
		return AttestationResult{Verified: false, Nonce: hex.EncodeToString(nonce), Verdict: err.Error()}, nil
	}
	return AttestationResult{
		Verified:    true,
		Type:        "nitro",
		Measurement: measurement,
		Nonce:       hex.EncodeToString(nonce),
		Verdict:     "verified",
		ChannelKey:  channelKey,
	}, nil
}

// endpointNitroFetch reads a base64 COSE_Sign1 document from the in-enclave agent's
// /attest endpoint (proxied over vsock by the parent instance).
func endpointNitroFetch(baseURL string) nitroFetch {
	return func(ctx context.Context, nonce []byte) ([]byte, error) {
		token, _, err := agent.FetchAttestation(ctx, baseURL, nonce)
		if err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(token)
	}
}
