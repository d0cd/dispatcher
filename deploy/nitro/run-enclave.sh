#!/usr/bin/env bash
# Run the enclave and start the parent-side vsock->TCP proxy so dispatcher can
# reach the in-enclave agent. Run on the Nitro parent instance.
#
#   sudo ./deploy/nitro/run-enclave.sh            # after build-eif.sh
#
# The enclave is untrusted from dispatcher's side (attestation + sealing are the
# boundary); the proxy just bridges the vsock channel to TCP :8443.
set -euo pipefail

EIF="${EIF:-dispatcher-attest-nitro.eif}"
CID="${CID:-16}"
CPUS="${CPUS:-2}"
MEM="${MEM:-512}" # MiB; raise for heavier workloads (enclave RAM is fixed at launch)
PORT="${PORT:-8443}"
PROXY="${PROXY:-./dispatcher-nitro-proxy}"

echo ">> terminating any running enclaves"
nitro-cli terminate-enclave --all >/dev/null 2>&1 || true

echo ">> run-enclave cid=$CID cpus=$CPUS mem=${MEM}MiB"
nitro-cli run-enclave --eif-path "$EIF" --cpu-count "$CPUS" --memory "$MEM" --enclave-cid "$CID"

echo ">> starting proxy :$PORT -> vsock($CID:$PORT)"
exec "$PROXY" --tcp ":$PORT" --cid "$CID" --vsock-port "$PORT"
