#!/usr/bin/env bash
# WARNING: this UKI path does NOT measure the agent. It builds a Unified Kernel
# Image (kernel+initrd+cmdline) measured into PCR4, but the agent is installed to
# /usr/local/bin on a MUTABLE, UNMEASURED root (root=…/cloudimg-rootfs) and is not
# pulled into the initrd — so PCR4 does not cover the agent binary and an attacker
# who modifies the image root could swap it without changing PCR4.
#
# Use the measured path instead: deploy/azure-uki/mkosi/ builds a dm-verity root
# whose roothash is injected into the UKI cmdline and measured into PCR11, which
# DOES attest the agent-carrying root. That is the flow the azure-snp adapter pins
# (DISPATCHER_AZURE_SNP_PCR11). This script remains only as a boot-mechanism
# reference; do not rely on it for a measured-agent guarantee.
#
#   sudo ./deploy/azure-uki/build-image.sh   # boot-mechanism reference only
#
# See docs/confidential-azure-uki.md for the mechanism and the Secure Boot fork.
set -euo pipefail

echo "WARNING: this UKI path does NOT measure the agent (mutable root); use deploy/azure-uki/mkosi/ (dm-verity -> PCR11) for a measured agent." >&2

AGENT_BIN="${AGENT_BIN:-./dispatcher-attest-azure}"
UNIT="$(dirname "$0")/dispatcher-attest-azure.service"
KVER="${KVER:-$(uname -r)}"
CMDLINE="${CMDLINE:-console=ttyS0 root=/dev/disk/by-label/cloudimg-rootfs ro}"
ESP="${ESP:-/boot/efi}"

command -v ukify >/dev/null || { echo "need systemd-ukify (apt install systemd-ukify)"; exit 1; }
[ -x "$AGENT_BIN" ] || { echo "agent binary not found at $AGENT_BIN"; exit 1; }

echo ">> 1. install agent + boot service"
install -m 0755 "$AGENT_BIN" /usr/local/bin/dispatcher-attest-azure
install -m 0644 "$UNIT" /etc/systemd/system/dispatcher-attest-azure.service
systemctl enable dispatcher-attest-azure.service

echo ">> 2. rebuild initrd (includes the agent unit via the enabled service)"
# The unit is enabled in the real root; the initrd hands off to it once the root
# is mounted. (For an initrd-resident agent, add a dracut module instead.)
update-initramfs -c -k "$KVER"

echo ">> 3. build the UKI (kernel + initrd + cmdline as one measured PE)"
ukify build \
  --linux="/boot/vmlinuz-${KVER}" \
  --initrd="/boot/initrd.img-${KVER}" \
  --cmdline="${CMDLINE}" \
  --output="/boot/dispatcher-uki.efi"

# 4. Make the UKI the firmware's boot application so it (not shim/grub) is the
#    thing measured into PCR4. VERIFY on the live build which of these the CVM
#    honors; the default-path write is the most portable.
echo ">> 4. install UKI as the default EFI boot application (VERIFY on live CVM)"
install -D -m 0644 "/boot/dispatcher-uki.efi" "${ESP}/EFI/BOOT/BOOTX64.EFI"

cat <<'NEXT'

>> Built /boot/dispatcher-uki.efi and staged it as the default boot app.
   Secure Boot fork (docs/confidential-azure-uki.md):
     - Secure Boot OFF (simpler): boots unsigned; PCR4 still measures the UKI.
     - Secure Boot ON: sbsign the UKI with a MOK-enrolled key first.
   Then: deprovision (waagent -deprovision+user), capture to a Shared Image
   Gallery image (ConfidentialVmSupported), boot a CVM from it, and read
   x-ms-azurevm-attested-pcr-values.pcr4 to pin as DISPATCHER_AZURE_PCR4.
NEXT
