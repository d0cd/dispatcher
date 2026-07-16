# Azure measured boot: measuring the agent into PCR11 (dm-verity root)

This closes the agent-not-measured caveat on Azure. The delivered path pins
**PCR11** (the dm-verity roothash carried in the UKI cmdline), captured as
`DISPATCHER_AZURE_SNP_PCR11` and built via `deploy/azure-uki/mkosi/`.

## Chosen approach: direct SNP+vTPM verification (no MAA)

Live-probing showed the shared MAA denies secure-boot-off, and MAA only attests
PCRs 0–7. So we follow **Constellation**: verify the SEV-SNP report + a
vTPM PCR **quote** directly, without MAA. That removes the MAA policy/secure-boot
obstacle entirely and lets us pin **PCR11** — where a UKI's components land —
instead of forcing the agent into PCR4. The verifier is built and TDD'd
(`verifyAzureSNP`, `internal/attest/azure_snp.go`): SEV-SNP report (genuine AMD)
→ `REPORT_DATA = SHA-256(runtime data)` → the vTPM AK (HCLAkPub) → an AK-signed
TPM quote over the PCRs → pin PCR11. The in-CVM agent (`go-tpm` + direct SNP+vTPM,
`internal/attest/agent/azuresnp`), the mkosi UKI image, and live validation are all
shipped and hardware-validated; the run attests and delivers the workload over an
attested TLS session (aTLS).

## Status

**✅ COMPLETE — measured boot live-validated end-to-end.**

- ✅ Verifier (`verifyAzureSNP` / `AzureSNPValidatorPinned`) + agent
  (`dispatcher-attest-azuresnp`) — direct SNP+vTPM, no MAA, pins PCR11.
- ✅ **Measured image built + live-validated.** A custom mkosi image bakes the
  agent into a **dm-verity root**; mkosi injects the verity **roothash into the UKI
  cmdline** (`roothash=…`), which systemd-stub measures into **PCR11**. The agent
  runs from the verity-protected read-only root (`systemd.volatile=overlay` gives a
  tmpfs upper for writes). So PCR11 attests the entire root — including the agent.
  Confirmed on a real CVM booted from this image: the full pipeline (attest over
  aTLS → verify PCR11 → deliver → run inside the CVM → result over the session)
  passed (`TestGolden_AzureSNPLiveExchange`). A changed agent → different roothash →
  different PCR11 → rejected before any secret is sealed.

Build flow: `deploy/azure-uki/mkosi/` (mkosi 27 from git; verity partitions in
`mkosi.repart/`) → VHD blob → ConfidentialVm gallery image → CVM via ARM template.
See `deploy/azure-uki/mkosi/build-and-upload.md`.

### Gotchas found live (all documented in the build flow)

- Stock Azure Ubuntu 24.04 CVM is snapd-immutable (no loose kernel/initrd) — can't
  modify in place; a purpose-built image is required. Its OS disk is plain ext4
  (`VMGuestStateOnly`), so PCR changes don't brick it.
- mkosi **20.2** (apt) and PyPI don't work on noble; install mkosi **from git** (v27).
- ConfidentialVm gallery images need a **VHD blob** source (not a managed disk).
- Register the `Microsoft.Storage` provider first.
- `az vm create` from a custom gallery image trips an az-CLI bug (2.88/Python 3.14);
  use an **ARM template** deployment instead.
