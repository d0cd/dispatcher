# Azure measured-image build (mkosi) — WIP scaffold

Builds a custom Azure Confidential VM image with `dispatcher-attest-azuresnp`
baked into a **UKI + dm-verity root**, so PCR11 attests the agent (consumed by
`attest.NewAzureSNPAttester`, which is done + live-validated). This is the one
remaining piece of Azure measured boot.

## Status: scaffold, not yet building cleanly

A live attempt (see `docs/confidential-azure-uki.md`) established the approach and
the obstacles. `mkosi.conf` here is the starting config. **It does not build on
Ubuntu 24.04 + mkosi 20.2** due to known ecosystem friction:

- Ubuntu 24.04 ships no `bootctl` (mkosi needs `bootctl kernel-identify`). A shim
  that answers `kernel-identify → unknown` unblocks it (`mkosi.skeleton/usr/bin/bootctl`).
- mkosi 20.2's default package lists reference pre-`t64` names (`libtss2-mu0` →
  `libtss2-mu-4.0.1-0t64`, and more behind it).

## Recommended path (dedicated effort)

Use a **newer mkosi** with a **Debian (bookworm) or Fedora base** — where UKI +
dm-verity build cleanly — rather than fighting Ubuntu 24.04. Or adopt
Constellation's prebuilt images. Then:

1. `Bootloader=uki`, verity-protected root (`mkosi.repart/` with `Verity=data`/`hash`)
   — mkosi injects the roothash into the UKI cmdline → measured into PCR11.
2. Bake the agent + `dispatcher-attest-azuresnp.service` (already in `mkosi.extra/`).
3. Azure boot: `linux-image-azure` (Hyper-V drivers) + `cloud-init` (Azure datasource).
4. Convert the image to a fixed VHD, upload to a Shared Image Gallery as
   `ConfidentialVmSupported`, boot a CVM (Secure Boot off is fine — we don't use MAA).
5. Capture PCR11 from the agent's evidence; pin as `DISPATCHER_AZURE_SNP_PCR11`.

The verifier and agent need no changes — they already consume this image's evidence.
