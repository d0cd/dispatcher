package cloudvm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/types"
)

func TestAttestationFromHandleState(t *testing.T) {
	raw, err := (&CloudVMState{Attestation: &attest.AttestationResult{Verified: true, Type: "sev-snp", Measurement: "abcd"}}).MarshalHandleState()
	require.NoError(t, err)
	att := attest.AttestationFromHandleState(raw)
	require.NotNil(t, att)
	assert.True(t, att.Verified)
	assert.Equal(t, "sev-snp", att.Type)

	noConf, err := (&CloudVMState{VMID: "x"}).MarshalHandleState()
	require.NoError(t, err)
	assert.Nil(t, attest.AttestationFromHandleState(noConf), "a non-confidential run has no verdict")
	assert.Nil(t, attest.AttestationFromHandleState(nil))
	assert.Nil(t, attest.AttestationFromHandleState(json.RawMessage("not json")))
}

func TestConfidentialPreflight(t *testing.T) {
	conf := types.WorkloadSpec{Requirements: types.ResourceRequirements{
		Confidential: types.ConfidentialRequirement{Required: true, Type: "sev-snp"}}}
	// The SSH-VM path has no verifier; every attestation-on run must fail closed
	// before provisioning (attestation-on is routed to the confidential adapter).
	require.Error(t, confidentialAttestationPreflight(conf, ProviderGCP))
	require.Error(t, confidentialAttestationPreflight(conf, ProviderAzure))
	require.Error(t, confidentialAttestationPreflight(conf, ProviderAWS))
	require.Error(t, confidentialAttestationPreflight(conf, ProviderHetzner))

	// attestation: off is the escape hatch — provision the TEE without verification.
	off := conf
	off.Requirements.Confidential.Attestation = "off"
	require.NoError(t, confidentialAttestationPreflight(off, ProviderGCP))
	require.NoError(t, confidentialAttestationPreflight(off, ProviderHetzner))
}

func TestVerifyConfidential_Off(t *testing.T) {
	res, err := verifyConfidential(context.Background(), ProviderGCP, &VMInfo{}, "", "",
		types.ConfidentialRequirement{Required: true, Attestation: "off"})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.False(t, res.Verified)
	assert.Contains(t, res.Verdict, "attestation off")
}
