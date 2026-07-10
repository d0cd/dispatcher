package cloudvm

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

// Secrets are sealed to the in-TEE channel key with HPKE (RFC 9180) base mode —
// a standard, not a hand-rolled construction. The suite is
// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305: the sender is
// anonymous (base mode), the ephemeral encapsulation gives forward secrecy, and
// only the holder of the recipient private key (the measured agent, whose public
// key is bound in the attestation report) can open the payload.
var (
	hpkeKEM   = hpke.KEM_X25519_HKDF_SHA256
	hpkeSuite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
)

// sealInfo is the HPKE `info` string binding a sealed payload to its purpose, so
// a ciphertext produced for this context can't be reinterpreted in another.
var sealInfo = []byte("dispatcher/confidential/seal/v1")

// newChannelKeypair generates the in-TEE channel keypair (X25519). The agent
// keeps the private key inside the TEE; the public key is what gets bound in the
// attestation evidence and handed to dispatcher to seal against.
func newChannelKeypair() (pub, priv []byte, err error) {
	pk, sk, err := hpkeKEM.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: generate channel keypair: %w", err)
	}
	pub, err = pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	priv, err = sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// sealToChannelKey encrypts plaintext to the recipient's X25519 public key. Only
// the matching private key (held by the measured in-TEE agent) can open it.
// Output is the HPKE encapsulation followed by the ciphertext.
func sealToChannelKey(recipientPub, plaintext []byte) ([]byte, error) {
	pk, err := hpkeKEM.Scheme().UnmarshalBinaryPublicKey(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("hpke: invalid recipient public key: %w", err)
	}
	sender, err := hpkeSuite.NewSender(pk, sealInfo)
	if err != nil {
		return nil, fmt.Errorf("hpke: new sender: %w", err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hpke: setup: %w", err)
	}
	ct, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("hpke: seal: %w", err)
	}
	return append(enc, ct...), nil
}

// openSealed decrypts a sealed payload with the recipient's private key. Used by
// the in-TEE agent (and the round-trip test).
func openSealed(recipientPriv, sealed []byte) ([]byte, error) {
	scheme := hpkeKEM.Scheme()
	sk, err := scheme.UnmarshalBinaryPrivateKey(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("hpke: invalid recipient private key: %w", err)
	}
	encSize := scheme.CiphertextSize() // the KEM encapsulation prefixing the payload
	if len(sealed) < encSize {
		return nil, fmt.Errorf("hpke: sealed payload too short (%d < %d)", len(sealed), encSize)
	}
	enc, ct := sealed[:encSize], sealed[encSize:]
	receiver, err := hpkeSuite.NewReceiver(sk, sealInfo)
	if err != nil {
		return nil, fmt.Errorf("hpke: new receiver: %w", err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("hpke: receiver setup: %w", err)
	}
	pt, err := opener.Open(ct, nil)
	if err != nil {
		return nil, fmt.Errorf("hpke: open (wrong key or tampered): %w", err)
	}
	return pt, nil
}
