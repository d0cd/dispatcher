package cloudvm

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

type stubAttester struct {
	result AttestationResult
	err    error
	called bool
}

func (s *stubAttester) Verify(_ context.Context, _ *VMInfo, _, _, _ string) (AttestationResult, error) {
	s.called = true
	return s.result, s.err
}

// withAttester registers an attester for a provider for the duration of a test.
func withAttester(t *testing.T, id ProviderID, a Attester) {
	t.Helper()
	prev, had := attesters[id]
	attesters[id] = a
	t.Cleanup(func() {
		if had {
			attesters[id] = prev
		} else {
			delete(attesters, id)
		}
	})
}

func TestConfidentialAttestationPreflight(t *testing.T) {
	required := types.WorkloadSpec{Requirements: types.ResourceRequirements{
		Confidential: types.ConfidentialRequirement{Required: true, Attestation: "required"},
	}}

	// No verifier registered → fail closed before provisioning.
	require.Error(t, confidentialAttestationPreflight(required, ProviderGCP))

	// attestation: off → allowed.
	off := types.WorkloadSpec{Requirements: types.ResourceRequirements{
		Confidential: types.ConfidentialRequirement{Required: true, Attestation: "off"},
	}}
	require.NoError(t, confidentialAttestationPreflight(off, ProviderGCP))

	// A verifier exists → preflight passes (the real check runs post-boot).
	withAttester(t, ProviderGCP, &stubAttester{result: AttestationResult{Verified: true}})
	require.NoError(t, confidentialAttestationPreflight(required, ProviderGCP))
}

func TestVerifyConfidential(t *testing.T) {
	vm := &VMInfo{ID: "vm1", IP: "1.2.3.4"}
	req := types.ConfidentialRequirement{Required: true, Type: "sev-snp", Attestation: "required"}

	t.Run("not confidential is a no-op", func(t *testing.T) {
		res, err := verifyConfidential(context.Background(), ProviderGCP, vm, "/k", "u", types.ConfidentialRequirement{})
		require.NoError(t, err)
		assert.Nil(t, res)
	})

	t.Run("attestation off is a no-op", func(t *testing.T) {
		res, err := verifyConfidential(context.Background(), ProviderGCP, vm, "/k", "u",
			types.ConfidentialRequirement{Required: true, Attestation: "off"})
		require.NoError(t, err)
		assert.Nil(t, res)
	})

	t.Run("verified records the result", func(t *testing.T) {
		stub := &stubAttester{result: AttestationResult{Verified: true, Type: "sev-snp", Verdict: "ok"}}
		withAttester(t, ProviderGCP, stub)
		res, err := verifyConfidential(context.Background(), ProviderGCP, vm, "/k", "u", req)
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.True(t, res.Verified)
		assert.True(t, stub.called)
	})

	t.Run("rejection aborts the run", func(t *testing.T) {
		withAttester(t, ProviderGCP, &stubAttester{result: AttestationResult{Verified: false, Verdict: "measurement mismatch"}})
		_, err := verifyConfidential(context.Background(), ProviderGCP, vm, "/k", "u", req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "attestation rejected")
		assert.Contains(t, err.Error(), "measurement mismatch")
	})

	t.Run("verifier error aborts the run", func(t *testing.T) {
		withAttester(t, ProviderGCP, &stubAttester{err: fmt.Errorf("KDS unreachable")})
		_, err := verifyConfidential(context.Background(), ProviderGCP, vm, "/k", "u", req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})
}
