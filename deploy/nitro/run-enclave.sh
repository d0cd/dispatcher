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
MEM="${MEM:-768}" # MiB; mirrors nitroEnclaveMemoryMiB in the Go path (confidential_nitro.go)
PORT="${PORT:-8443}"
PROXY="${PROXY:-./dispatcher-nitro-proxy}"

echo ">> run-enclave cid=$CID cpus=$CPUS mem=${MEM}MiB"
# Capture THIS enclave's id and tear down only it on exit — never `--all`, which
# would kill co-located enclaves the same operator may be running.
RUN_JSON="$(nitro-cli run-enclave --eif-path "$EIF" --cpu-count "$CPUS" --memory "$MEM" --enclave-cid "$CID")"
echo "$RUN_JSON"
ENCLAVE_ID="$(printf '%s' "$RUN_JSON" | sed -n 's/.*"EnclaveID"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
if [ -n "$ENCLAVE_ID" ]; then
  trap 'nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" >/dev/null 2>&1 || true' EXIT
fi

echo ">> starting proxy :$PORT -> vsock($CID:$PORT)"
exec "$PROXY" --tcp ":$PORT" --cid "$CID" --vsock-port "$PORT"
