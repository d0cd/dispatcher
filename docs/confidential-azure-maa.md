# Azure confidential runs (MAA) — design

**Status:** implemented + live-validated end-to-end (the MAA adapter is run-reachable and hardware-validated; measured-boot PCR pinning remains infra-gated). Azure confidential VMs are
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

## Grounded findings (from a real captured token)

The assumed schema was wrong; a live capture corrected it:
- SEV-SNP facts are **nested under `x-ms-isolation-tee`** (`attestation-type`,
  `compliance-status`, `launchmeasurement`, `is-debuggable`), not top-level.
- The channel-key binding rides in the top-level
  **`x-ms-runtime.client-payload.nonce`** (base64), set to
  `SHA-256(runNonce ‖ channelKey)` — **32 bytes** to fit the TPM quote's
  qualifying data (SHA-512 is rejected `TPM_RC_SIZE`).
- Keys come from the pinned MAA instance's **`/certs`** JWKS (`x5c`).
- The pure-Go agent uses the maintained **edgelesssys/go-azguestattestation**
  library (vTPM → HCL → MAA REST) — no C++ dependency, no reinvented parser.

## Status
1. ✅ Verifier corrected + golden-validated against a real token (`verifyMAAToken`,
   nested schema, client-payload binding, `/certs` x5c keys; signatures on go-jose).
2. ✅ In-TEE agent: the generalized HTTP sealed-exchange agent attesting via MAA
   (`azureagent.RunAgent`, `cmd/dispatcher-attest-azure`) + `endpointMAAFetch`.
3. ✅ MAA JWKS load + issuer pin (`LoadAzureMAAKeys`).
4. ✅ Full-R9 sealing — reused directly (the agent runs the same sealed exchange).
5. ✅ Orchestration core (`executeAzureConfidential`, verify-before-seal, unit-tested).
6. ✅ **Live end-to-end on a real SEV-SNP CVM** (`TestGolden_AzureLiveExchange`):
   attest via MAA over the endpoint → verify → seal `.env` → run in the TEE →
   sealed result; the sealed secret reached the workload inside the TEE.

7. ✅ **Production `dispatcher run` wiring** — `AzureConfidentialAdapter` (full
   TargetAdapter), `azureStartAgent` (SSH scp + start + NSG), `OpenAgentPort`,
   and run-selection routing (confidential Azure → this path; fails closed without
   `DISPATCHER_AZURE_AGENT_BIN`). **Integrated live-validated end-to-end**
   (`TestGolden_AzureLiveAdapter`): provision → agent → attest → seal → run → result
   → Cleanup, reaped to $0. The operator pins the launch measurement in
   `confidential.measurements` (set by the CVM image).

## Trust caveat (important)

Unlike GCP Confidential Space — where the **container image digest is the attested
measurement**, so attestation proves the agent — the AMD SEV-SNP **launch
measurement covers only the CVM firmware, not the OS or the scp'd agent**. Absent
measured boot, the path assumes the SSH delivery channel and the host do not
substitute a different agent.

### Closing it: measured boot via the vTPM (PCR pinning)

Azure CVMs have a vTPM whose boot-chain measurements MAA attests in
`x-ms-azurevm-attested-pcr-values` (PCRs 0–7). **PCR4** is the boot application
measurement: bake `dispatcher-attest-azure` into a **Unified Kernel Image** (kernel
+ initrd-with-agent + cmdline as one signed EFI binary) in a custom CVM image, and
the agent's identity is anchored in PCR4 — which MAA reports.

The **verifier half is implemented**: `MAAPolicy` pins PCR values and requires
secure boot (`verifyMAAToken` enforces them; see `MAAMeasuredBoot`). Configure the
pin per run:

```
DISPATCHER_AZURE_PCR4=<base64 sha256 from a known-good measured image>
DISPATCHER_AZURE_PCR0=<...>   # optional: firmware
DISPATCHER_AZURE_PCR7=<...>   # optional: secure-boot state
DISPATCHER_AZURE_REQUIRE_SECUREBOOT=1
```

With no pin set, behavior is unchanged (firmware-only attestation — the caveat
stands). The **remaining, infra-gated half** is building the custom UKI CVM image
and capturing its known-good PCR4 to pin — flagged in `azureStartAgent`.
