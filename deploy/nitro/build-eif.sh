#!/usr/bin/env bash
# Build the enclave image into an EIF and print its PCR measurements. Run on a
# Nitro-enabled parent instance (needs docker + aws-nitro-enclaves-cli). The
# printed PCR0 is what dispatcher pins as the attested enclave measurement.
#
#   ./deploy/nitro/build-eif.sh            # from the repo root
#
# Capture the "Measurements" block from the output; PCR0 goes into
# DISPATCHER_AWS_NITRO_PCR0 for the run.
set -euo pipefail

IMAGE="${IMAGE:-dispatcher-attest-nitro:latest}"
EIF="${EIF:-dispatcher-attest-nitro.eif}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo ">> docker build $IMAGE"
docker build -t "$IMAGE" -f "$REPO_ROOT/deploy/nitro/Dockerfile" "$REPO_ROOT"

echo ">> nitro-cli build-enclave -> $EIF"
nitro-cli build-enclave --docker-uri "$IMAGE" --output-file "$EIF"

echo ">> PCR measurements (pin PCR0 as DISPATCHER_AWS_NITRO_PCR0):"
nitro-cli describe-eif --eif-path "$EIF" | grep -A6 '"Measurements"'
