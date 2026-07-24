package agent

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
