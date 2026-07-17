#!/usr/bin/env bash
#
# capture-snp.sh — run ON a freshly-booted AMD SEV-SNP confidential VM (GCP n2d
# or AWS M6a/C6a/R6a). Captures a real attestation report + the AMD certificate
# chain into fixture files the golden test consumes.
#
# Prerequisites on the VM:
#   - /dev/sev-guest present (the sev-guest kernel module; on recent Ubuntu CVM
#     images it is loaded automatically inside a SEV-SNP guest).
#   - snpguest installed: https://github.com/virtee/snpguest
#       cargo install snpguest        # or grab a release binary
#
# NOTE: snpguest's subcommand syntax has changed across releases. If a command
# below errors, check `snpguest --help` / `snpguest <cmd> --help` and adjust —
# the goal is simply to land report.bin + report-data.hex + {vcek,ask,ark}.pem.
set -euo pipefail
umask 077

OUT=${1:-./snp-out}
# Processor model the KDS keys are fetched for: milan | genoa | turin | ...
# Must match the host CPU. Override: MODEL=milan ./capture-snp.sh
MODEL=${MODEL:-genoa}

mkdir -p "$OUT"

if [[ ! -e /dev/sev-guest ]]; then
  echo "error: /dev/sev-guest not present — is this a SEV-SNP guest with the sev-guest module loaded?" >&2
  exit 1
fi
command -v snpguest >/dev/null || { echo "error: snpguest not installed (see header)" >&2; exit 1; }

# 1. Request an attestation report with random REPORT_DATA. snpguest writes the
#    64-byte request data it used to report-data.bin; we record its hex so the
#    golden test can confirm the REPORT_DATA offset round-trips.
snpguest report "$OUT/report.bin" "$OUT/report-data.bin" --random
xxd -p -c 64 "$OUT/report-data.bin" | tr -d '\n' > "$OUT/report-data.hex"

# 2. Fetch the AMD cert chain from the Key Distribution Service (KDS).
#    'fetch ca' yields the ARK (root) + ASK (intermediate); 'fetch vcek' yields
#    the leaf keyed by this report's chip id + reported TCB.
snpguest fetch ca pem "$MODEL" "$OUT"
snpguest fetch vcek pem "$MODEL" "$OUT" "$OUT/report.bin"

echo
echo "captured into $OUT:"
ls -1 "$OUT"
echo
echo "Expected by the golden test: report.bin report-data.hex vcek.pem ask.pem ark.pem"
echo "If snpguest named the certs differently (e.g. *.crt or genoa-specific names),"
echo "rename them to vcek.pem / ask.pem / ark.pem before copying to fixtures/snp/."
