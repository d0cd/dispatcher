package agent

import (
	"encoding/base64"
	"encoding/json"
)

// AzureSNPEvidence is the direct-verification evidence an Azure confidential VM's
// agent returns (Constellation-style, no MAA): the SEV-SNP report + cert chain,
// the HCL runtime data (which binds the vTPM Attestation Key), and an AK-signed
// TPM quote over the PCRs. It is a pure wire type shared by the in-CVM agent that
// produces it and the dispatcher-side verifier that consumes it — no dependencies.
type AzureSNPEvidence struct {
	SNPReport   []byte            `json:"snp_report"`   // raw 0x4a0 SEV-SNP report
	VCEK        []byte            `json:"vcek"`         // VCEK leaf DER
	ASK         []byte            `json:"ask"`          // ASK intermediate DER
	RuntimeData []byte            `json:"runtime_data"` // HCL runtime data (carries HCLAkPub)
	Quote       []byte            `json:"quote"`        // TPMS_ATTEST the AK signed
	QuoteSig    []byte            `json:"quote_sig"`    // raw RSA signature over Quote by the AK
	PCRs        map[uint32][]byte `json:"pcrs"`         // PCR index → value
	ChannelKey  []byte            `json:"channel_key"`  // agent's X25519 sealing pubkey
}

// AssembleAzureSNP packs the gathered SEV-SNP + vTPM parts into the base64(JSON)
// wire evidence the dispatcher-side verifier parses. It is the single source of
// truth for the Azure evidence field mapping and encoding, shared by the in-CVM
// issuer that produces it and the round-trip test that exercises it, so the
// producer and verifier cannot silently diverge. channelKey is advisory: the
// verifier binds the aTLS session key, not this field.
func AssembleAzureSNP(snpReport, runtimeData, vcek, ask, quote, quoteSig []byte, pcrs map[uint32][]byte, channelKey []byte) (string, error) {
	raw, err := json.Marshal(AzureSNPEvidence{
		SNPReport:   snpReport,
		VCEK:        vcek,
		ASK:         ask,
		RuntimeData: runtimeData,
		Quote:       quote,
		QuoteSig:    quoteSig,
		PCRs:        pcrs,
		ChannelKey:  channelKey,
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
