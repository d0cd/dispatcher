package attest

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeal_RoundTrip(t *testing.T) {
	pub, priv, err := newChannelKeypair()
	require.NoError(t, err)

	for _, pt := range [][]byte{[]byte("source tarball + .env"), {}, bytes.Repeat([]byte{0x5A}, 4096)} {
		sealed, err := sealToChannelKey(pub, pt)
		require.NoError(t, err)
		assert.NotEqual(t, pt, sealed, "the payload must not appear in the clear")

		opened, err := openSealed(priv, sealed)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(pt, opened), "round-trip must recover the plaintext")
	}
}

func TestSeal_WrongKeyFails(t *testing.T) {
	pub, _, err := newChannelKeypair()
	require.NoError(t, err)
	_, otherPriv, err := newChannelKeypair()
	require.NoError(t, err)

	sealed, err := sealToChannelKey(pub, []byte("secret"))
	require.NoError(t, err)

	_, err = openSealed(otherPriv, sealed)
	require.Error(t, err, "a different private key must not open the payload")
}

func TestSeal_TamperFails(t *testing.T) {
	pub, priv, err := newChannelKeypair()
	require.NoError(t, err)
	sealed, err := sealToChannelKey(pub, []byte("secret"))
	require.NoError(t, err)

	sealed[len(sealed)-1] ^= 0xFF // flip a ciphertext byte

	_, err = openSealed(priv, sealed)
	require.Error(t, err, "AEAD integrity must reject a tampered payload")
}

func TestSeal_RejectsBadRecipientKey(t *testing.T) {
	_, err := sealToChannelKey([]byte("not-an-x25519-key"), []byte("x"))
	require.Error(t, err)
}
