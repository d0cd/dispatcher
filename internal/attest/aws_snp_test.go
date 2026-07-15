package attest

import (
	"context"
	"testing"

	"github.com/google/go-sev-guest/verify/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/types"
)

// TestPinARK_RejectsMismatchedRoot proves the ARK pinning rejects a chain whose
// root is not go-sev-guest's embedded AMD root — the defense against a compromised
// KDS/DNS substituting a fake self-signed root.
func TestPinARK_RejectsMismatchedRoot(t *testing.T) {
	genoa := trust.DefaultRootCerts["Genoa"]
	if genoa == nil || genoa.ProductCerts == nil || genoa.ProductCerts.Ark == nil {
		t.Skip("no embedded Genoa root to use as a mismatched ARK")
	}
	// A chain carrying Genoa's ARK, checked against Milan's pinned root → mismatch.
	pc := &trust.ProductCerts{Ark: genoa.ProductCerts.Ark}
	err := pinARKAndCheckRevocation(pc, "Milan")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match the pinned")
}

func TestAWSAttester_NotReadyAndNoFetch(t *testing.T) {
	_, err := (&awsSNPAttester{}).Verify(context.Background(),
		types.ConfidentialRequirement{Required: true, Type: "sev-snp"})
	require.Error(t, err, "no fetch wired must error, not panic")
}

func TestAWSAttester_PropagatesFetchFailure(t *testing.T) {
	att := &awsSNPAttester{
		fetchChain: func(string) ([]byte, error) { return nil, nil },
		fetch: func(_ context.Context, _ []byte) (snpEvidence, error) {
			return snpEvidence{}, assertErr("/dev/sev-guest unavailable")
		}}
	_, err := att.Verify(context.Background(),
		types.ConfidentialRequirement{Required: true, Type: "sev-snp", Measurements: []string{"x"}})
	require.Error(t, err, "a fetch failure is an error, not an unverified verdict")
}

func TestVerifyAWSSNPReport_RejectsGarbage(t *testing.T) {
	_, err := verifyAWSSNPReport([]byte("not a report"), func(string) ([]byte, error) { return nil, nil })
	require.Error(t, err, "malformed report bytes must error, not panic")
}
