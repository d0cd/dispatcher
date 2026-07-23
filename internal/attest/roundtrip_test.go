package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/attest/agent"
	"github.com/d0cd/dispatcher/internal/attest/atls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These round-trip tests drive the FULL confidential channel end to end: the real
// atls handshake, the real bindData derivation on BOTH ends (H(peerSPKI‖exporter)),
// the real IssuerFromAttest wiring, the shared binding function, the real evidence
// assembly, and the real per-cloud validator. The only stand-in is the TEE hardware
// core (the vTPM quote / SNP report / NSM COSE document), which is produced here
// with test keys in the genuine wire format — that boundary is irreducible without
// real hardware.
//
// What they lock that no other test does: the value the atls layer computes as
// bindData on the agent side is EXACTLY what the validator recomputes on the
// dispatcher side, and the evidence must commit to it. A drift in the binding, the
// wire format, or the handshake exporter would break these even though every
// component's own unit test still passes.

// runATLS performs one attested handshake over an in-memory pipe: the issuer serves
// the agent side, the validator runs the dispatcher side. It returns the
// dispatcher-side ClientAttest verdict (nil = the peer is a genuine measured TEE
// bound to this session).
func runATLS(t *testing.T, issuer atls.Issuer, validator atls.Validator) error {
	t.Helper()
	serverCfg, spki, err := atls.NewServerConfig()
	require.NoError(t, err)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	sTLS := tls.Server(serverConn, serverCfg)
	cTLS := tls.Client(clientConn, atls.NewClientConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The server runs concurrently (net.Pipe is synchronous, so the handshake needs
	// both ends live). The deferred send always fires — even if a require inside the
	// issuer's evidence builders were to Goexit this goroutine — so the drain below
	// can never hang the test.
	srvErr := make(chan error, 1)
	go func() {
		var e error
		defer func() { srvErr <- e }()
		e = atls.ServerAttest(ctx, sTLS, spki, issuer)
	}()

	cliErr := atls.ClientAttest(ctx, cTLS, validator)
	<-srvErr
	return cliErr
}

// --- Azure SEV-SNP backend -------------------------------------------------

// azureRoundTrip holds the static per-session crypto material (built once in the
// test goroutine) so the AttestFunc closure only has to sign a quote over the
// handshake-derived binding and assemble the evidence.
type azureRoundTrip struct {
	t           *testing.T
	ch          snpChain
	akPriv      *rsa.PrivateKey
	runtimeData []byte
	report      []byte
	pcrs        map[uint32][]byte
	roots       []*x509.Certificate
	pcrPolicy   map[int]string
	measurement string
}

func newAzureRoundTrip(t *testing.T) *azureRoundTrip {
	t.Helper()
	ch := newSNPChain(t)
	installCRL(t, arkSignedCRL(t, ch)) // nothing revoked
	akPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	runtimeData := runtimeDataWithAK(t, &akPriv.PublicKey)
	var reportData [64]byte
	rdHash := sha256.Sum256(runtimeData)
	copy(reportData[:], rdHash[:]) // Azure binds SHA-256(runtimeData) into REPORT_DATA

	pcr11 := make48(0xAB)[:32]
	return &azureRoundTrip{
		t:           t,
		ch:          ch,
		akPriv:      akPriv,
		runtimeData: runtimeData,
		report:      buildSNPReport(t, make48(0x11), reportData[:], 9, 0, ch.vcekKey),
		pcrs:        map[uint32][]byte{11: pcr11},
		roots:       []*x509.Certificate{ch.ark},
		pcrPolicy:   map[int]string{11: hex.EncodeToString(pcr11)},
		measurement: hex.EncodeToString(make48(0x11)),
	}
}

// issuer builds an atls.Issuer that quotes over the session binding. When
// bindOverride is non-nil it commits to THAT value instead of the real session
// bindData, modeling a relayed/substituted attestation.
func (a *azureRoundTrip) issuer(bindOverride []byte) atls.Issuer {
	return agent.IssuerFromAttest(func(_ context.Context, nonce, bindData []byte) (string, error) {
		commit := bindData
		if bindOverride != nil {
			commit = bindOverride
		}
		quote, sig := signedQuote(a.t, a.akPriv, a.pcrs, agent.MAABindingNonce(nonce, commit))
		return agent.AssembleAzureSNP(a.report, a.runtimeData, a.ch.vcek.Raw, a.ch.ask.Raw, quote, sig, a.pcrs, commit)
	})
}

func (a *azureRoundTrip) validator(measurement string) atls.Validator {
	return AzureSNPValidator(a.roots, a.pcrPolicy, measurement, 0)
}

func TestATLSRoundTrip_AzureSNP_Accepts(t *testing.T) {
	a := newAzureRoundTrip(t)
	require.NoError(t, runATLS(t, a.issuer(nil), a.validator(a.measurement)),
		"valid Azure SNP evidence bound to this session must verify end to end")
}

func TestATLSRoundTrip_AzureSNP_RejectsUnboundEvidence(t *testing.T) {
	a := newAzureRoundTrip(t)
	// The issuer commits to a different key than the TLS session actually used —
	// exactly a MITM/relay presenting valid evidence for the wrong channel.
	err := runATLS(t, a.issuer(make([]byte, 32)), a.validator(a.measurement))
	require.Error(t, err, "evidence not bound to this session's key must be rejected")
	assert.Contains(t, err.Error(), "attestation rejected")
}

func TestATLSRoundTrip_AzureSNP_RejectsMeasurementMismatch(t *testing.T) {
	a := newAzureRoundTrip(t)
	err := runATLS(t, a.issuer(nil), a.validator(hex.EncodeToString(make48(0x22))))
	require.Error(t, err, "a launch measurement other than the pinned one must be rejected")
	assert.Contains(t, err.Error(), "attestation rejected")
}

// --- AWS Nitro backend -----------------------------------------------------

type nitroRoundTrip struct {
	t         *testing.T
	root      *x509.Certificate
	rootKey   *ecdsa.PrivateKey
	pool      *x509.CertPool
	pcrPolicy map[int]string
}

func newNitroRoundTrip(t *testing.T) *nitroRoundTrip {
	t.Helper()
	root, rootKey := nitroTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &nitroRoundTrip{
		t:         t,
		root:      root,
		rootKey:   rootKey,
		pool:      pool,
		pcrPolicy: map[int]string{0: hex.EncodeToString(nitroPCR(0x0A))},
	}
}

// issuer builds an atls.Issuer that stamps the session nonce + binding into the
// NSM document. pubOverride, when non-nil, commits a different public_key than the
// session key (a relayed attestation).
func (n *nitroRoundTrip) issuer(pubOverride []byte) atls.Issuer {
	return agent.IssuerFromAttest(func(_ context.Context, nonce, bindData []byte) (string, error) {
		pub := bindData
		if pubOverride != nil {
			pub = pubOverride
		}
		doc := signedNitroDoc(n.t, n.root, n.rootKey, func(d *nitroDoc) {
			d.Nonce = nonce
			d.PublicKey = pub
		})
		return base64.StdEncoding.EncodeToString(doc), nil
	})
}

func (n *nitroRoundTrip) validator(pcrs map[int]string) atls.Validator {
	return NitroValidator(n.pool, pcrs)
}

func TestATLSRoundTrip_Nitro_Accepts(t *testing.T) {
	n := newNitroRoundTrip(t)
	require.NoError(t, runATLS(t, n.issuer(nil), n.validator(n.pcrPolicy)),
		"valid Nitro evidence bound to this session must verify end to end")
}

func TestATLSRoundTrip_Nitro_RejectsUnboundEvidence(t *testing.T) {
	n := newNitroRoundTrip(t)
	err := runATLS(t, n.issuer(make([]byte, 32)), n.validator(n.pcrPolicy))
	require.Error(t, err, "a Nitro document bound to the wrong channel key must be rejected")
	assert.Contains(t, err.Error(), "attestation rejected")
}

func TestATLSRoundTrip_Nitro_RejectsPCRMismatch(t *testing.T) {
	n := newNitroRoundTrip(t)
	err := runATLS(t, n.issuer(nil), n.validator(map[int]string{0: hex.EncodeToString(nitroPCR(0xFF))}))
	require.Error(t, err, "a PCR0 other than the pinned one must be rejected")
	assert.Contains(t, err.Error(), "attestation rejected")
}
