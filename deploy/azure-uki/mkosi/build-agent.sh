#!/usr/bin/env bash
# Build dispatcher-attest-azuresnp reproducibly inside the SAME digest-pinned Go
# toolchain container the Nitro enclave uses (deploy/nitro/Dockerfile), so the
# agent baked into the measured (PCR11) dm-verity root does not depend on whatever
# Go happens to be installed on the builder host. The output lands in
# mkosi.extra/usr/local/bin/ where mkosi bakes it into the measured root.
#
# Keep GOLANG_IMAGE in sync with deploy/nitro/Dockerfile (resolve with
# deploy/nitro/resolve-base-digests.sh). Re-run this, rebuild the image, and
# re-capture + re-pin PCR11 whenever the agent source or the toolchain changes.
#
#   deploy/azure-uki/mkosi/build-agent.sh
set -euo pipefail

GOLANG_IMAGE="golang:1.25.12@sha256:d2e20dc1b35aefd666909163e4ace41efb521359aa2ce31fff59d86837050f6f"

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
out_rel="deploy/azure-uki/mkosi/mkosi.extra/usr/local/bin/dispatcher-attest-azuresnp"

mkdir -p "${script_dir}/mkosi.extra/usr/local/bin"

# -trimpath strips builder-absolute paths so the binary is path-independent;
# CGO_ENABLED=0 keeps it static and free of host libc. The pinned image fixes the
# exact toolchain, bringing the azure-snp agent under the same hash as Nitro.
docker run --rm \
  -v "${repo_root}:/src" -w /src \
  -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
  "${GOLANG_IMAGE}" \
  go build -trimpath -o "/src/${out_rel}" ./cmd/dispatcher-attest-azuresnp

echo "built ${out_rel} with ${GOLANG_IMAGE}"
