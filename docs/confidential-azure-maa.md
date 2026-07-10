# Azure confidential runs (MAA) — design

**Status:** design, grounded by a live spike. Azure confidential VMs are
SSH-able SEV-SNP VMs, so they run through the existing `CloudVMAdapter` +
`verifyConfidential` → `azureAttester` flow — much more reuse than GCP CS. But a
live spike (Ubuntu 24.04 CVM, `Standard_DC2ads_v5`) turned up findings that
change the binding and the agent.

## What's already built (reused as-is)
- `verifyMAAToken` — JWS verify (MAA JWKS) + compliance + TEE type → `Claims`.
- `azureAttester.Verify` — nonce → fetch → verify → policy; `isReady`/`fetch` seams.
- Azure CVM provisioning (`ConfidentialVM` security type, vTPM, secure boot,
  `cvm` image).
- `seal.go` (HPKE) for the approved full-R9 sealing.

## Live spike findings (the ground truth)
1. **No `/dev/sev-guest`.** The CVM (kernel `6.17-azure-fde`) exposes attestation
   only through the **vTPM** (`/dev/tpm0`); the Azure HCL/SNP report lives in NV
   index `0x01400001`. So the *raw* SEV-SNP path isn't available on Azure —
   confirming the vendor (MAA) decision — and the report is fetched via TPM, not
   a sev-guest ioctl.
2. **The channel-key binding cannot use SNP `REPORT_DATA`.** The vTPM SNP
   report's `report_data` is fixed at boot (bound to the vTPM AK), not settable
   per request. So the existing `applyPolicy` binding
   (`REPORT_DATA == SHA-512(nonce ‖ channelKey)`, built for the GCP/AWS sev-guest
   path) **does not apply to Azure**. On the MAA path, freshness + key binding
   ride in the **MAA runtime data**: the guest supplies a nonce + channel key in
   the attestation request, and MAA echoes them in the token's `x-ms-runtime`
   claim (a hash also lands in the report via the AK, but the token claim is the
   check). The verifier must gain a runtime-data binding check distinct from the
   REPORT_DATA one.
3. **MAA is reachable** from the guest (`sharedeus.eus.attest.azure.net` → 200),
   so the vendor round-trip works.

## The on-VM agent (the real work)
An SSH-invoked agent that: generates the channel keypair → reads the HCL/SNP
report from the vTPM (`tpm2` NV read of `0x01400001`) → builds the MAA
`/attest/SevSnpVm` request with runtime data carrying `nonce ‖ channelKey` →
POSTs to the MAA instance → returns `(token, channelKey)`. Then `maaFetch` SSHes
in, runs it, parses stdout — mirroring the GCP `dispatcher-attest` agent but on
the SSH-VM model and the vTPM/MAA protocol.

**Build fork:** implement the HCL-report + MAA REST protocol ourselves (full
control, more code, must track Azure's proprietary HCL wrapper format), or embed
Microsoft's guest-attestation library (`libazguestattestation`, C++ — less
protocol code, a native dependency in the agent image).

## Binding redesign (verifier)
Add an `x-ms-runtime` claim to `maaToken` and a runtime-data binding check:
`hash(runtime-data) commits to SHA-256/512(nonce ‖ channelKey)`. Keep the
existing REPORT_DATA binding for the raw path; the MAA path uses the new one.
This is the Azure analog of the CS `eat_nonce` channel-key binding.

## Full-R9 delivery (approved)
After a verified MAA verdict, seal source/`.env` to the attested channel key and
unseal on-VM before running — the same sealing step the SSH path lacks today
(reuse `seal.go`; agent gains a seal-open + exec, like `dispatcher-attest`).

## Phasing
1. Verifier binding: `x-ms-runtime` + runtime-data channel-key check (TDD, offline).
2. On-VM MAA agent (vTPM read → MAA REST → token+key) + `maaFetch` wiring.
3. MAA JWKS load + issuer pin; flip `azureAttester.isReady`.
4. Full-R9 seal on the SSH path.
5. Live end-to-end on a real CVM.
