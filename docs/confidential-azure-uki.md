# Azure measured boot: baking the agent into PCR4 (UKI)

This closes the agent-not-measured caveat on Azure. The verifier half is already
done (`MAAMeasuredBoot` / `DISPATCHER_AZURE_PCR*`, see `docs/confidential-azure-maa.md`);
this doc is the **image build** that produces a known-good PCR4 to pin.

## Why PCR4, and why a UKI

MAA attests vTPM **PCRs 0–7** (confirmed from a real token:
`x-ms-azurevm-attested-pcrs: [0..7]`). The agent's measurement must therefore land
in one of 0–7. The boot chain measures things as:

| PCR | Measures |
| --- | --- |
| 0 | firmware (OVMF) |
| 4 | **boot application(s) the firmware/shim launches** (Authenticode hash) |
| 5 | boot config / GPT |
| 7 | secure-boot state + the signature used |
| 9 | (grub) kernel/initrd it loads — **not attested** |
| 11–14 | (systemd-stub UKI sections, MOK) — **not attested** |

So the agent-in-initrd measured by grub lands in PCR9 (not attested), and a
systemd-boot-chainloaded UKI lands in PCR11 (not attested). **The only attested
lever is PCR4.** The firmware measures every EFI application it `LoadImage`s into
PCR4. So the agent must be *inside the EFI boot application itself* — a **Unified
Kernel Image** (kernel + initrd-with-agent + cmdline as one PE binary) that the
firmware launches directly. Then `PCR4 = H(shim) ⊕ H(UKI)` covers the agent, and
pinning PCR4 attests the exact kernel+initrd+agent that booted.

## The secure-boot fork (the real decision)

Azure Confidential VMs boot with Secure Boot on and Microsoft's keys in `db`.
Firmware will only `LoadImage` a UKI whose signature chains to `db` (or a
MOK-enrolled key). Two ways to satisfy that:

1. **Keep MS shim + MOK-enroll a custom key, sign the UKI with it.** PCR7 stays
   the normal Azure-CVM secure-boot state (attestation compliance intact); the MOK
   change lands in PCR14 (not attested). *Obstacle:* `mokutil --import` needs an
   interactive MokManager confirmation at the next boot — hard to automate on Azure
   (no easy console).

2. **Secure Boot off, pin PCR4 alone.** An unsigned UKI boots; the firmware still
   measures it into PCR4. Secure Boot *prevents booting* an unsigned image; PCR4
   pinning *detects* a swapped image — and detection is all we need, because
   dispatcher verifies **before** sealing (a swapped UKI → different PCR4 →
   attestation rejected → no secret shipped). The verifier sets
   `RequireSecureBoot=false` for this image and pins PCR4 (+ PCR0). *Open
   question:* whether the CVM security type permits Secure Boot off while keeping
   the SEV-SNP `azure-compliant-cvm` verdict — to confirm on the live build.

For our threat model (verify-before-seal), option 2 is the simpler path in
principle: PCR4 pinning alone anchors the agent, and the SEV-SNP launch
measurement still proves genuine Azure CVM firmware.

### Live finding (2026-07): the default MAA policy blocks option 2

A live test settled the open question. Azure **does** let you create a CVM with
Secure Boot off (`--enable-secure-boot false`), the agent runs, and MAA egress
works — but the **shared MAA instance's default policy denies attestation when
`secureboot==false`**:

```
PolicyValidationFailure: [type=="secureboot", value==false] => deny();
```

So option 2 needs a **custom MAA instance** whose policy permits `secureboot==false`
while still requiring a genuine SEV-SNP `azure-compliant-cvm` (and echoing the
PCRs). The dispatcher verifier then pins that custom MAA as the issuer and pins
PCR4. Option 1 (Secure Boot on, MS-signed shim) avoids the custom policy but needs
the UKI signed by a `db`/MOK key, and MOK enrollment (`mokutil --import`) requires
an interactive MokManager confirmation at the next boot — awkward to automate on
Azure. **Neither path is a one-command build**; both are viable with more work.

## Build recipe

On an Ubuntu 24.04 CVM builder (has `systemd-ukify`, `binutils`, the kernel):

1. Install the agent + a oneshot systemd unit that starts it at boot
   (`deploy/azure-uki/dispatcher-attest-azure.service`).
2. Build an initrd that includes the agent + the unit (dracut/mkinitramfs).
3. Build the UKI binding kernel + initrd + cmdline:

   ```
   ukify build \
     --linux=/boot/vmlinuz-$(uname -r) \
     --initrd=/boot/initrd.img-agent \
     --cmdline="root=... console=ttyS0" \
     --output=/boot/efi/EFI/BOOT/BOOTX64.EFI     # firmware's default boot app
   ```

   (Option 1 also: `sbsign --key MOK.key --cert MOK.crt` the UKI and MOK-enroll.)
4. Make the UKI the firmware boot entry (write it to the ESP default path, or
   `efibootmgr` a Boot#### pointing at it).
5. Generalize (`waagent -deprovision+user`) and capture to a Shared Image Gallery
   image with `ConfidentialVmSupported`.

`deploy/azure-uki/build-image.sh` scripts steps 1–4.

## Capture PCR4 + pin it

1. Provision a CVM from the gallery image (Secure Boot per the fork above).
2. Fetch an MAA token (the agent's `/attest`, or the Azure guest-attestation
   client) and read `x-ms-azurevm-attested-pcr-values.pcr4`.
3. Pin it for runs:

   ```
   DISPATCHER_AZURE_PCR4=<pcr4 from step 2>
   # + DISPATCHER_AZURE_REQUIRE_SECUREBOOT=1 only if the image keeps Secure Boot on
   ```

The verifier then rejects any CVM whose booted UKI (kernel+initrd+agent) isn't the
pinned one. PCR4 is content-addressed — it changes on every agent/kernel rebuild,
so re-capture and re-pin per image.

## Status

- ✅ Verifier (`MAAMeasuredBoot`, PCR pinning) — done and unit-tested.
- ✅ Build assets + recipe (this doc, `deploy/azure-uki/`).
- ✅ Live-probed the fork: CVM Secure-Boot-off is accepted + the agent/MAA egress
  work, but the shared MAA denies `secureboot==false` (finding above).
- ⏳ Remaining live build: stand up a custom MAA instance with a policy that
  permits `secureboot==false` (option 2), OR solve MOK-signed UKI under Secure
  Boot on (option 1); then build the UKI image, capture PCR4, and validate.
