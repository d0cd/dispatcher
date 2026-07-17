package agent

import (
	"context"

	"github.com/d0cd/dispatcher/internal/attest/atls"
)

// IssuerFromAttest adapts an AttestFunc into an atls.Issuer. The per-cloud
// producers already bind H(nonce || boundKey) into their evidence; the aTLS layer
// simply passes bindData (the session key||exporter commitment) in the boundKey
// slot, so the report/token commits to the TLS session instead of a bare channel
// key handed out over the untrusted endpoint.
func IssuerFromAttest(attest AttestFunc) atls.Issuer {
	return issuerAdapter{attest: attest}
}

type issuerAdapter struct{ attest AttestFunc }

func (i issuerAdapter) Issue(ctx context.Context, bindData, nonce []byte) ([]byte, error) {
	token, err := i.attest(ctx, nonce, bindData)
	if err != nil {
		return nil, err
	}
	return []byte(token), nil
}
